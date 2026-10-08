// Package fields reads a Provider's plain field map for its Factory.
package fields

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/dnsgateway/dnsprovider"
)

// Check refuses a field map holding a field the Provider does not take,
// such as a misspelt one, which would otherwise be dropped unseen. The
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

	sort.Strings(unknown)

	return fmt.Errorf("%s: unknown field %s", provider, strings.Join(unknown, ", "))
}
