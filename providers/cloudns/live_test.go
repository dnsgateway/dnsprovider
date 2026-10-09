package cloudns_test

import (
	"os"
	"testing"

	"github.com/dnsgateway/dnsprovider/internal/livetest"
	"github.com/dnsgateway/dnsprovider/providers/cloudns"
)

// TestLive only reads DNS, and skips without a password and one auth mode.
func TestLive(t *testing.T) {
	f := cloudns.Factory()
	// The common harness requires all listed secrets. Select the configured
	// alternative identity while keeping every selected field secret.
	chosen := cloudns.FieldAuthID
	count := 0
	for _, name := range []string{cloudns.FieldAuthID, cloudns.FieldSubAuthID, cloudns.FieldSubAuthUser} {
		if os.Getenv(livetest.Env("cloudns", name)) != "" {
			chosen = name
			count++
		}
	}
	if count > 1 {
		t.Fatal("set exactly one ClouDNS authentication identity")
	}
	selected := f.Fields[:0]
	for _, fd := range f.Fields {
		if fd.Name == cloudns.FieldPassword || fd.Name == chosen {
			selected = append(selected, fd)
		}
	}
	f.Fields = selected
	livetest.Run(t, "cloudns", f)
}
