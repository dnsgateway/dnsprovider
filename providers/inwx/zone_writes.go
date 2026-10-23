package inwx

import (
	"context"
	"errors"
	"fmt"

	"github.com/dnsgateway/dnsprovider"
)

// nameservers are the nameservers INWX serves its zones from, which
// CreateZone gives a new zone. They are those of INWX's zones, not yet
// confirmed by a capture.
var nameservers = []string{"ns.inwx.de", "ns2.inwx.de", "ns3.inwx.eu"}

// CreateZone implements dnsprovider.Provider: it Onboards the name as a
// master zone on INWX's nameservers with one nameserver.create, never
// repeated, and no web, mail or URL-redirect options. It calls no
// domain method, so the Registration and Delegation are untouched. The
// Zone has the answer's roId as its ID, the nameservers sent, and an
// Unknown Hosting State; an answer without a roId is the Zone's name
// alone. A zone INWX already hosts is ErrConflict.
func (p *Provider) CreateZone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	name, err := namedZone(name)
	if err != nil {
		return dnsprovider.Zone{}, err
	}

	ns := append([]string{}, nameservers...)

	env, err := p.write(ctx, "nameserver.create", map[string]any{"domain": name, "type": "MASTER", "ns": ns}, pendingTaken)
	if err != nil {
		return dnsprovider.Zone{}, fmt.Errorf("inwx: Onboard %q: %w", name, err)
	}

	var res struct {
		RoID wireInt `json:"roId"`
	}

	// The create took; an answer that does not say what it made leaves
	// the Zone its name alone.
	z := dnsprovider.Zone{Name: name, State: dnsprovider.HostingUnknown}
	if decode(env.ResData, &res) == nil && res.RoID > 0 {
		z.ID, z.Nameservers = res.RoID.String(), ns
	}

	return z, nil
}

// DeleteZone implements dnsprovider.Provider: it Offboards the Zone and
// its Records with one nameserver.delete by name, never repeated, and
// calls no domain method, so the Registration and Delegation are
// untouched. The zone of that name is read first: one gone, or whose
// roId is not zone.ID (it was deleted and created again), is ErrNotFound,
// without the delete. When the delete's outcome is unknown (a lost
// answer, a server error or failure code, an undecodable answer), the
// zone is read once more: gone is success, as this delete took it;
// still there, or unreadable, is the Unconfirmed Write.
func (p *Provider) DeleteZone(ctx context.Context, zone dnsprovider.Zone) error {
	name, err := namedZone(zone.Name)
	if err != nil {
		return err
	}

	id, err := p.hosted(ctx, name)
	if err != nil {
		return fmt.Errorf("inwx: Offboard %q: %w", name, err)
	}

	if id.String() != zone.ID {
		return fmt.Errorf("inwx: Offboard %q: the zone of that name is %s, not %q: %w", name, id, zone.ID, dnsprovider.ErrNotFound)
	}

	_, err = p.write(ctx, "nameserver.delete", map[string]any{"domain": name}, pendingTaken)
	if err == nil {
		return nil
	}

	if !errors.Is(err, dnsprovider.ErrUnconfirmed) {
		return fmt.Errorf("inwx: Offboard %q: %w", name, err)
	}

	if _, rerr := p.hosted(ctx, name); errors.Is(rerr, dnsprovider.ErrNotFound) {
		return nil
	}

	return fmt.Errorf("inwx: Offboard %q: %w", name, err)
}

// hosted is the roId of the zone of that name INWX hosts, read from
// nameserver.info filtered to its SOA; ErrNotFound when INWX hosts none.
// Unlike GetZone, it never reads the Registration.
func (p *Provider) hosted(ctx context.Context, name string) (wireInt, error) {
	info, err := p.zoneInfo(ctx, "", map[string]any{"domain": name, "type": "SOA"})
	if err != nil {
		return 0, err
	}

	if got := zoneName(info.Domain); got != name {
		return 0, fmt.Errorf("inwx: nameserver.info for %q answered another zone", name)
	}

	return info.RoID, nil
}
