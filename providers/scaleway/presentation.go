package scaleway

import (
	"fmt"
	"strings"

	"github.com/dnsgateway/dnsprovider/internal/charstr"
)

// txtValue joins the quoted character strings of one TXT record.
func txtValue(s string) (string, error) {
	values, err := charstr.Parse(s, " \t")
	if err != nil {
		return "", fmt.Errorf("scaleway: %w", err)
	}
	return strings.Join(values, ""), nil
}
