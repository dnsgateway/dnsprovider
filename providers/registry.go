// Package providers gathers every adapter in this module into one
// dnsprovider.Registry, for a consumer that picks its Provider at run
// time. A consumer that knows its Provider imports that package alone.
package providers

import (
	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/cloudflare"
	"github.com/dnsgateway/dnsprovider/providers/cloudns"
	"github.com/dnsgateway/dnsprovider/providers/digitalocean"
	"github.com/dnsgateway/dnsprovider/providers/dnsimple"
	"github.com/dnsgateway/dnsprovider/providers/gandi"
	"github.com/dnsgateway/dnsprovider/providers/godaddy"
	"github.com/dnsgateway/dnsprovider/providers/internetbs"
	"github.com/dnsgateway/dnsprovider/providers/namecheap"
	"github.com/dnsgateway/dnsprovider/providers/porkbun"
	"github.com/dnsgateway/dnsprovider/providers/vultr"
)

// Registry returns a new Registry with one Factory per adapter, by
// Provider type.
func Registry() dnsprovider.Registry {
	return dnsprovider.Registry{
		"cloudflare":   cloudflare.Factory(),
		"cloudns":      cloudns.Factory(),
		"digitalocean": digitalocean.Factory(),
		"dnsimple":     dnsimple.Factory(),
		"godaddy":      godaddy.Factory(),
		"gandi":        gandi.Factory(),
		"internetbs":   internetbs.Factory(),
		"namecheap":    namecheap.Factory(),
		"porkbun":      porkbun.Factory(),
		"vultr":        vultr.Factory(),
	}
}
