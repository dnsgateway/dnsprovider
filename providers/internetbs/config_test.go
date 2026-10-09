package internetbs_test

import (
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider/providers/internetbs"
)

func TestNewValidatesCredentialsWithoutNetwork(t *testing.T) {
	for _, cfg := range []internetbs.Config{{}, {Key: "key"}, {Password: "password"}, {Key: " ", Password: "password"}, {Key: "key", Password: "\t"}} {
		p, err := internetbs.New(cfg)
		if p != nil || err == nil || strings.Contains(err.Error(), "password\t") {
			t.Fatalf("invalid config accepted: %v", err)
		}
	}
	if _, err := internetbs.New(internetbs.Config{Key: "key", Password: "password"}); err != nil {
		t.Fatal(err)
	}
}
