package cloudflare_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider/providers/cloudflare"
)

// TestLive reads a real Cloudflare Account, without writing to it. It is skipped
// unless DNSPROVIDER_CLOUDFLARE_TOKEN holds an API token; DNSPROVIDER_CLOUDFLARE_BASE_URL may point it at
// another endpoint, such as a sandbox.
func TestLive(t *testing.T) {
	token := os.Getenv("DNSPROVIDER_CLOUDFLARE_TOKEN")
	if token == "" {
		t.Skip("DNSPROVIDER_CLOUDFLARE_TOKEN is not set")
	}

	p, err := cloudflare.Config{BaseURL: os.Getenv("DNSPROVIDER_CLOUDFLARE_BASE_URL")}.New(token)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if _, err := p.Nameservers(ctx); err != nil {
		t.Fatalf("Nameservers: %v", err)
	}

	zones, err := p.Zones(ctx)
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	for _, z := range zones {
		if z.ID == "" || z.Name == "" {
			t.Errorf("Zone %+v has no ID or Name", z)
		}
	}

	if len(zones) == 0 {
		return
	}

	if _, err := p.Records(ctx, zones[0]); err != nil {
		t.Fatalf("Records(%s): %v", zones[0].Name, err)
	}
}
