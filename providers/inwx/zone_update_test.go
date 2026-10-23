package inwx_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/inwx"
)

func updateZone(d *dnssecFake, zone dnsprovider.Zone, u dnsprovider.ZoneUpdate) (dnsprovider.ZoneStatus, error) {
	return d.provider().UpdateZone(context.Background(), zone, u)
}

// switches are the calls of the DNSSEC switch the fake received.
func (d *dnssecFake) switches() []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.switchesLocked()
}

// switchesLocked is switches for a handler, which holds the fake's lock.
func (d *dnssecFake) switchesLocked() []string {
	var out []string

	for _, c := range d.calls {
		if c.method == "dnssec.enablednssec" || c.method == "dnssec.disablednssec" {
			out = append(out, c.method)
		}
	}

	return out
}

func TestTraitsDeclareZoneUpdate(t *testing.T) {
	d := newDNSSECFake(t)

	if !dnsprovider.Can(d.provider(), dnsprovider.CapZoneUpdater) || !inwx.Factory().Can(dnsprovider.CapZoneUpdater) {
		t.Error("the Traits do not declare CapZoneUpdater")
	}
}

func TestUpdateZoneTurnsINWXsSigningOnWithOneEnableCall(t *testing.T) {
	d := newDNSSECFake(t)
	on := true

	got, err := updateZone(d, unsigned, dnsprovider.ZoneUpdate{DNSSEC: &on})
	if err != nil {
		t.Fatal(err)
	}

	if want := (dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On}); got != want {
		t.Errorf("UpdateZone = %+v, want %+v", got, want)
	}

	if s := d.switches(); !slices.Equal(s, []string{"dnssec.enablednssec"}) {
		t.Fatalf("switches = %v, want one enablednssec", s)
	}

	if p := d.params("dnssec.enablednssec"); p["domainName"] != "example.org" {
		t.Errorf("enablednssec params = %v, want domainName example.org", p)
	}
}

func TestUpdateZoneTurnsINWXsSigningOffWithOneDisableCall(t *testing.T) {
	d := newDNSSECFake(t)
	off := false

	got, err := updateZone(d, signed, dnsprovider.ZoneUpdate{DNSSEC: &off})
	if err != nil {
		t.Fatal(err)
	}

	if want := (dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Off}); got != want {
		t.Errorf("UpdateZone = %+v, want %+v", got, want)
	}

	if s := d.switches(); !slices.Equal(s, []string{"dnssec.disablednssec"}) {
		t.Fatalf("switches = %v, want one disablednssec", s)
	}

	if p := d.params("dnssec.disablednssec"); p["domainName"] != "example.com" {
		t.Errorf("disablednssec params = %v, want domainName example.com", p)
	}
}

func TestUpdateZoneSendsTheSwitchEvenToTheStateAlreadyRead(t *testing.T) {
	d := newDNSSECFake(t)
	on := true

	if _, err := updateZone(d, signed, dnsprovider.ZoneUpdate{DNSSEC: &on}); err != nil {
		t.Fatal(err)
	}

	if s := d.switches(); !slices.Equal(s, []string{"dnssec.enablednssec"}) {
		t.Fatalf("switches = %v, want one enablednssec though the zone is AUTO", s)
	}
}

func TestUpdateZoneReadsBackTheSwitch(t *testing.T) {
	for _, tc := range []struct {
		name   string
		on     bool
		settle string // the status the switch leaves
		failed bool   // the read-back fails
		want   dnsprovider.Setting
		zone   dnsprovider.Zone
	}{
		{name: "on, still NONE", on: true, settle: "NONE", want: dnsprovider.Pending, zone: unsigned},
		{name: "on, UPDATE", on: true, settle: "UPDATE", want: dnsprovider.Pending, zone: unsigned},
		{name: "off, still AUTO", on: false, settle: "AUTO", want: dnsprovider.Pending, zone: signed},
		{name: "off, DELETE_ALL", on: false, settle: "DELETE_ALL", want: dnsprovider.Pending, zone: signed},
		{name: "off, MANUAL", on: false, settle: "MANUAL", want: dnsprovider.Off, zone: signed},
		{name: "on, read-back fails", on: true, failed: true, want: dnsprovider.Unknown, zone: unsigned},
	} {
		d := newDNSSECFake(t)
		if tc.settle != "" {
			d.settleOn[tc.on] = tc.settle
		}

		d.handle("dnssec.info", func(r *request) string {
			if tc.failed && slices.Contains(d.switchesLocked(), "dnssec.enablednssec") {
				return refusal(2400, "SYNTHETIC: internal error")
			}

			return d.info(r)
		})

		on := tc.on

		got, err := updateZone(d, tc.zone, dnsprovider.ZoneUpdate{DNSSEC: &on})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}

		if got.DNSSEC != tc.want {
			t.Errorf("%s: DNSSEC = %v, want %v", tc.name, got.DNSSEC, tc.want)
		}
	}
}

func TestUpdateZoneTakesAPendingAnswerAsTaken(t *testing.T) {
	d := newDNSSECFake(t)
	d.script("dnssec.enablednssec", http.StatusOK, answer(1001, nil))
	on := true

	got, err := updateZone(d, unsigned, dnsprovider.ZoneUpdate{DNSSEC: &on})
	if err != nil {
		t.Fatalf("UpdateZone answered 1001 = %v, want taken", err)
	}

	// The scripted answer applied nothing: the read-back still shows NONE.
	if got.DNSSEC != dnsprovider.Pending {
		t.Errorf("DNSSEC = %v, want pending", got.DNSSEC)
	}
}

func TestUpdateZoneReportsAnUnsettledSwitchAsUnconfirmed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"lost answer", lost, ""},
		{"2400", http.StatusOK, refusal(2400, "SYNTHETIC: internal error")},
		{"2500", http.StatusOK, `{"code":2500,"msg":"Command failed; server closing connection"}`},
		{"HTTP 502", http.StatusBadGateway, "bad gateway"},
		{"undecodable", http.StatusOK, "<html>"},
		{"no code", http.StatusOK, `{"msg":"?"}`},
	} {
		d := newDNSSECFake(t)
		d.script("dnssec.enablednssec", tc.status, tc.body)
		on := true

		_, err := updateZone(d, unsigned, dnsprovider.ZoneUpdate{DNSSEC: &on})
		if !errors.Is(err, dnsprovider.ErrUnconfirmed) {
			t.Errorf("%s: err = %v, want ErrUnconfirmed", tc.name, err)
		}

		if s := d.switches(); len(s) != 1 {
			t.Errorf("%s: switches = %v, want one, never replayed", tc.name, s)
		}
	}
}

func TestUpdateZoneSendsTheSwitchAgainOnceWhenINWXRefusedItsSession(t *testing.T) {
	d := newDNSSECFake(t)
	p := d.provider()
	on := true

	if _, err := p.GetZone(context.Background(), unsigned.Name); err != nil {
		t.Fatal(err)
	}

	// The session expires between the zone's read and the switch.
	d.handle("nameserver.info", func(r *request) string {
		answer := d.fake.info(r)
		clear(d.sessions)

		return answer
	})

	got, err := p.UpdateZone(context.Background(), unsigned, dnsprovider.ZoneUpdate{DNSSEC: &on})
	if err != nil || got.DNSSEC != dnsprovider.On {
		t.Fatalf("UpdateZone = %+v, %v, want DNSSEC on", got, err)
	}

	if s := d.switches(); len(s) != 2 {
		t.Fatalf("switches = %v, want the refused one and one sent again", s)
	}

	if logins, _, _ := d.stats(); logins != 2 {
		t.Errorf("logins = %d, want 2", logins)
	}
}

func TestUpdateZoneReturnsAClientRefusalAsARefusal(t *testing.T) {
	d := newDNSSECFake(t)
	d.scriptCode("dnssec.enablednssec", 2304, "SYNTHETIC: status prohibits")
	on := true

	_, err := updateZone(d, unsigned, dnsprovider.ZoneUpdate{DNSSEC: &on})

	var apiErr *dnsprovider.APIError
	if !errors.As(err, &apiErr) || errors.Is(err, dnsprovider.ErrUnconfirmed) {
		t.Fatalf("err = %v, want the APIError, not unconfirmed", err)
	}

	if s := d.switches(); len(s) != 1 {
		t.Errorf("switches = %v, want one", s)
	}
}

func TestUpdateZoneRefusesAZoneINWXDoesNotHostWithoutAWrite(t *testing.T) {
	for _, tc := range []struct {
		zone dnsprovider.Zone
		want error
	}{
		{dnsprovider.Zone{Name: "example.net"}, dnsprovider.ErrNotServed}, // registered, not hosted
		{dnsprovider.Zone{Name: "stranger.example"}, dnsprovider.ErrNotFound},
		{dnsprovider.Zone{}, dnsprovider.ErrNotFound},
	} {
		d := newDNSSECFake(t)
		on := true

		_, err := updateZone(d, tc.zone, dnsprovider.ZoneUpdate{DNSSEC: &on})
		if !errors.Is(err, tc.want) {
			t.Errorf("%q: err = %v, want %v", tc.zone.Name, err, tc.want)
		}

		if s := d.switches(); len(s) != 0 {
			t.Errorf("%q: switches = %v, want none", tc.zone.Name, s)
		}
	}
}

func TestUpdateZoneRefusesHSTSAndMinTLSAfterTheDNSSECSwitch(t *testing.T) {
	on, hsts := true, true
	tls := dnsprovider.TLS12

	for _, u := range []dnsprovider.ZoneUpdate{
		{DNSSEC: &on, HSTS: &hsts},
		{DNSSEC: &on, MinTLS: &tls},
	} {
		d := newDNSSECFake(t)

		got, err := updateZone(d, unsigned, u)
		if !errors.Is(err, dnsprovider.ErrUnsupported) {
			t.Fatalf("err = %v, want ErrUnsupported", err)
		}

		if got.DNSSEC != dnsprovider.On {
			t.Errorf("DNSSEC = %v, want on, the switch kept", got.DNSSEC)
		}

		if s := d.switches(); !slices.Equal(s, []string{"dnssec.enablednssec"}) {
			t.Errorf("switches = %v, want one enablednssec", s)
		}
	}
}

func TestUpdateZoneReadsANilDNSSEC(t *testing.T) {
	d := newDNSSECFake(t)

	got, err := updateZone(d, signed, dnsprovider.ZoneUpdate{})
	if err != nil || got.DNSSEC != dnsprovider.On {
		t.Fatalf("UpdateZone = %+v, %v, want DNSSEC on", got, err)
	}

	hsts := false

	got, err = updateZone(d, signed, dnsprovider.ZoneUpdate{HSTS: &hsts})
	if !errors.Is(err, dnsprovider.ErrUnsupported) || got.DNSSEC != dnsprovider.On {
		t.Fatalf("UpdateZone(HSTS) = %+v, %v, want DNSSEC on and ErrUnsupported", got, err)
	}

	if s := d.switches(); len(s) != 0 {
		t.Errorf("switches = %v, want none", s)
	}

	d.scriptCode("dnssec.info", 2400, "SYNTHETIC: internal error")

	if _, err := updateZone(d, signed, dnsprovider.ZoneUpdate{}); err == nil {
		t.Error("UpdateZone of nothing succeeded with its read failing")
	}
}
