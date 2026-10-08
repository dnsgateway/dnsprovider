// Package fields reads a Provider's plain field map for its Factory.
package fields

import (
	"fmt"
	"slices"
	"strings"

	"github.com/dnsgateway/dnsprovider"
)

// Check refuses a field map holding a field the Provider does not take,
// such as a misspelled one, which would otherwise be dropped unseen. The
// error names the field, never its value.
func Check(provider string, known []dnsprovider.Field, m map[string]string) error {
	var unknown []string

	for name := range m {
		if !slices.ContainsFunc(known, func(f dnsprovider.Field) bool { return f.Name == name }) {
			unknown = append(unknown, name)
		}
	}

	if len(unknown) == 0 {
		return nil
	}

	slices.Sort(unknown)

	return fmt.Errorf("%s: unknown field %s", provider, strings.Join(unknown, ", "))
}

// Factory is a dnsprovider.Factory taking the fields fs: its New refuses
// a field not in fs (see Check), then builds the Provider with build,
// which refuses a missing required field. A failed build returns a nil
// Provider, never a typed nil.
func Factory[P dnsprovider.Provider](
	provider string,
	fs []dnsprovider.Field,
	build func(m map[string]string, opts ...dnsprovider.Option) (P, error),
) dnsprovider.Factory {
	return dnsprovider.Factory{
		Fields: fs,
		New: func(m map[string]string, opts ...dnsprovider.Option) (dnsprovider.Provider, error) {
			if err := Check(provider, fs, m); err != nil {
				return nil, err
			}

			p, err := build(m, opts...)
			if err != nil {
				return nil, err
			}

			return p, nil
		},
	}
}
