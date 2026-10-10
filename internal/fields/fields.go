// Package fields reads a Provider's plain field map for its Factory.
package fields

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/dnsgateway/dnsprovider"
)

// Check refuses a field map holding a field the Provider does not take,
// such as a misspelled one, which would otherwise be dropped unseen.
func Check(provider string, known []dnsprovider.Field, m map[string]string) error {
	var unknown []string

	for name := range m {
		if !slices.ContainsFunc(known, func(f dnsprovider.Field) bool { return f.Name == name }) {
			unknown = append(unknown, name)
		}
	}

	if len(unknown) > 0 {
		slices.Sort(unknown)

		return fmt.Errorf("%s: unknown field %s", provider, strings.Join(unknown, ", "))
	}

	return nil
}

// CheckDefaults refuses fields declaring a Default not among their
// Choices, which New would otherwise fill in and then refuse.
func CheckDefaults(provider string, known []dnsprovider.Field) error {
	for _, f := range known {
		if f.Default != "" && len(f.Choices) > 0 && !slices.Contains(f.Choices, f.Default) {
			return fmt.Errorf("%s: field %s declares a default not among its choices", provider, f.Name)
		}
	}

	return nil
}

// CheckChoices refuses a field map holding a value not among its field's
// Choices. The error names the field, never its value.
func CheckChoices(provider string, known []dnsprovider.Field, m map[string]string) error {
	for _, f := range known {
		if v := m[f.Name]; v != "" && len(f.Choices) > 0 && !slices.Contains(f.Choices, v) {
			return fmt.Errorf("%s: field %s must be one of %s", provider, f.Name, strings.Join(f.Choices, ", "))
		}
	}

	return nil
}

// Fill returns a copy of m with each missing or empty field of known that
// has a Default set to it. It leaves m as it is.
func Fill(known []dnsprovider.Field, m map[string]string) map[string]string {
	out := maps.Clone(m)
	if out == nil {
		out = map[string]string{}
	}

	for _, f := range known {
		if f.Default != "" && out[f.Name] == "" {
			out[f.Name] = f.Default
		}
	}

	return out
}

// Factory is a dnsprovider.Factory taking the fields fs: its New refuses
// every field map when fs declares a Default not among its Choices (see
// CheckDefaults), a field not in fs (see Check) and a value not among its
// Choices (see CheckChoices), fills in defaults (see Fill), then builds
// the Provider with build, which refuses a missing required field. A
// failed build returns a nil Provider, never a typed nil.
func Factory[P dnsprovider.Provider](
	provider string,
	fs []dnsprovider.Field,
	build func(m map[string]string, opts ...dnsprovider.Option) (P, error),
) dnsprovider.Factory {
	declared := CheckDefaults(provider, fs)

	return dnsprovider.Factory{
		Fields: fs,
		New: func(m map[string]string, opts ...dnsprovider.Option) (dnsprovider.Provider, error) {
			if declared != nil {
				return nil, declared
			}

			if err := Check(provider, fs, m); err != nil {
				return nil, err
			}

			if err := CheckChoices(provider, fs, m); err != nil {
				return nil, err
			}

			p, err := build(Fill(fs, m), opts...)
			if err != nil {
				return nil, err
			}

			return p, nil
		},
	}
}
