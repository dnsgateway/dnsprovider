package ovhcloud_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/ovhcloud"
)

func writeFake(t *testing.T) *fake {
	t.Helper()

	f := newFake(t)
	f.addZone("example.com",
		wireRecord{ID: 11, FieldType: "A", SubDomain: "www", Target: "192.0.2.1", TTL: 0},
		wireRecord{ID: 12, FieldType: "A", SubDomain: "www", Target: "192.0.2.2", TTL: 0},
		wireRecord{ID: 13, FieldType: "TXT", SubDomain: "", Target: `"hello"`, TTL: 300},
	)

	return f
}

func (f *fake) zone() *fakeZone {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.zones["example.com"]
}

func (f *fake) published(id string) (wireRecord, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	n, _ := strconv.ParseInt(id, 10, 64)
	r, ok := f.zones["example.com"].published[n]

	return r, ok
}

func read(t *testing.T, p dnsprovider.Provider) map[string]dnsprovider.Record {
	t.Helper()

	rs, err := p.Records(context.Background(), testZone, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	out := map[string]dnsprovider.Record{}
	for _, r := range rs.Records {
		out[r.ID] = r
	}

	return out
}

func TestSingleCRUDStagesRefreshesAndReturnsStoredRecords(t *testing.T) {
	f := writeFake(t)
	p := f.provider(t)
	ctx := context.Background()

	created, err := p.CreateRecord(ctx, testZone, dnsprovider.Record{Type: "MX", Name: "@", Value: "10 Mail.Example.com", TTL: 600})
	if err != nil {
		t.Fatal(err)
	}

	if created.ID == "" || created.Name != "example.com" || created.Value != "10 mail.example.com." || created.TTL != 600 {
		t.Fatalf("created = %+v", created)
	}

	if w, ok := f.published(created.ID); !ok || w.Target != "10 mail.example.com." || w.SubDomain != "" || w.FieldType != "MX" {
		t.Fatalf("not published: %+v", w)
	}

	if !slices.Equal(f.mutations(), []string{"POST /domain/zone/example.com/record", "POST /domain/zone/example.com/refresh"}) {
		t.Fatalf("mutations = %v", f.mutations())
	}

	after := created
	after.Value, after.TTL = "20 mx.example.net.", 900

	updated, err := p.UpdateRecord(ctx, testZone, created, after)
	if err != nil || updated.ID != created.ID || updated.Value != "20 mx.example.net." || updated.TTL != 900 {
		t.Fatalf("updated = %+v, %v", updated, err)
	}

	if w, _ := f.published(created.ID); w.Target != "20 mx.example.net." || w.TTL != 900 {
		t.Fatalf("update not published: %+v", w)
	}

	if err := p.DeleteRecord(ctx, testZone, updated); err != nil {
		t.Fatal(err)
	}

	if _, ok := f.published(created.ID); ok {
		t.Fatal("deletion not published")
	}

	if got := f.zone().refreshes; got != 3 {
		t.Fatalf("refreshes = %d, want one per CRUD call", got)
	}
}

func TestCreateRejectsIdenticalRecordsRegardlessOfTTL(t *testing.T) {
	f := writeFake(t)
	p := f.provider(t)

	for _, r := range []dnsprovider.Record{
		{Type: "A", Name: "WWW", Value: "192.0.2.1", TTL: 60},
		{Type: "TXT", Name: "example.com.", Value: `"hello"`, TTL: 3600},
	} {
		if _, err := p.CreateRecord(context.Background(), testZone, r); !errors.Is(err, dnsprovider.ErrConflict) {
			t.Fatalf("duplicate %+v = %v", r, err)
		}
	}

	if _, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "URI", Name: "x", Value: `10 1 "https://example.com/"`, TTL: 300}); err == nil {
		t.Fatal("unsupported type accepted")
	}

	if _, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "A", Name: "x", Value: "192.0.2.9", TTL: 1}); err == nil {
		t.Fatal("TTL out of range accepted")
	}

	if len(f.mutations()) != 0 {
		t.Fatalf("mutations = %v", f.mutations())
	}
}

func TestUpdatePreservesSiblingsInheritanceAndDeletesOnlyTheSelected(t *testing.T) {
	f := writeFake(t)
	p := f.provider(t)
	before := read(t, p)["11"]

	if before.TTL != 3600 {
		t.Fatalf("inherited TTL read as %d", before.TTL)
	}

	after := before
	after.Value = "192.0.2.3"

	stored, err := p.UpdateRecord(context.Background(), testZone, before, after)
	if err != nil || stored.ID != "11" || stored.Value != "192.0.2.3" || stored.TTL != 3600 {
		t.Fatalf("update = %+v, %v", stored, err)
	}

	if w := f.zone().staged[11]; w.TTL != 0 {
		t.Fatalf("inheritance lost: %+v", w)
	}

	rs := read(t, p)
	if rs["12"].Value != "192.0.2.2" || len(rs) != 3 {
		t.Fatalf("siblings = %+v", rs)
	}

	if err := p.DeleteRecord(context.Background(), testZone, rs["11"]); err != nil {
		t.Fatal(err)
	}

	if err := p.DeleteRecord(context.Background(), testZone, rs["12"]); err != nil {
		t.Fatal(err)
	}

	if rs := read(t, p); len(rs) != 1 || rs["13"].ID == "" {
		t.Fatalf("after deleting the last sibling: %+v", rs)
	}

	if err := p.DeleteRecord(context.Background(), testZone, rs["12"]); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatal("deleting a missing Record is not ErrNotFound")
	}

	missing := dnsprovider.Record{ID: "999", Type: "A", Name: "gone.example.com", Value: "192.0.2.9", TTL: 300}
	if _, err := p.UpdateRecord(context.Background(), testZone, missing, missing); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("update missing = %v", err)
	}
}

func TestContentLookupAgreesWithReadPresentation(t *testing.T) {
	f := newFake(t)
	f.addZone("example.com",
		wireRecord{ID: 21, FieldType: "PTR", SubDomain: "1", Target: "Host.Example.net.", TTL: 300},
		wireRecord{ID: 22, FieldType: "DNAME", SubDomain: "old", Target: "new", TTL: 300},
		wireRecord{ID: 23, FieldType: "SPF", SubDomain: "", Target: "v=spf1 -all", TTL: 300},
	)
	p := f.provider(t)

	for _, r := range []dnsprovider.Record{
		{Type: "PTR", Name: "1.example.com", Value: "host.example.net"},
		{Type: "DNAME", Name: "old.example.com", Value: "new.example.com"},
		{Type: "SPF", Name: "example.com", Value: "v=spf1 -all"},
	} {
		if err := p.DeleteRecord(context.Background(), testZone, r); err != nil {
			t.Errorf("delete %s by content = %v", r.Type, err)
		}
	}
}

func TestUpdateRejectsCollisions(t *testing.T) {
	f := writeFake(t)
	p := f.provider(t)
	rs := read(t, p)

	after := rs["11"]
	after.Value = "192.0.2.2"

	if _, err := p.UpdateRecord(context.Background(), testZone, rs["11"], after); !errors.Is(err, dnsprovider.ErrConflict) {
		t.Fatalf("collision = %v", err)
	}

	if len(f.mutations()) != 0 {
		t.Fatalf("mutations = %v", f.mutations())
	}
}

func TestTypeMoveReplacesTheRecord(t *testing.T) {
	f := writeFake(t)
	p := f.provider(t)
	before := read(t, p)["11"]

	after := dnsprovider.Record{Type: "CNAME", Name: "alias", Value: "target.example.net", TTL: 600}

	stored, err := p.UpdateRecord(context.Background(), testZone, before, after)
	if err != nil {
		t.Fatal(err)
	}

	if stored.ID == "11" || stored.ID == "" || stored.Type != "CNAME" || stored.Value != "target.example.net." || stored.Name != "alias.example.com" {
		t.Fatalf("moved = %+v", stored)
	}

	if !slices.Equal(f.mutations(), []string{"POST /domain/zone/example.com/record", "DELETE /domain/zone/example.com/record/11", "POST /domain/zone/example.com/refresh"}) {
		t.Fatalf("mutations = %v", f.mutations())
	}

	if _, ok := f.published("11"); ok {
		t.Fatal("old Record still published")
	}

	if _, ok := f.published(stored.ID); !ok {
		t.Fatal("new Record not published")
	}
}

func TestTypeMoveKeepsTTLInheritance(t *testing.T) {
	f := writeFake(t)
	p := f.provider(t)
	before := read(t, p)["11"]

	stored, err := p.UpdateRecord(context.Background(), testZone, before, dnsprovider.Record{Type: "AAAA", Name: "www", Value: "2001:db8::1", TTL: before.TTL})
	if err != nil || stored.TTL != 3600 {
		t.Fatalf("moved = %+v, %v", stored, err)
	}

	if w := f.zone().staged[mustID(t, stored.ID)]; w.TTL != 0 {
		t.Fatalf("inheritance lost on a type move: %+v", w)
	}

	// An explicit TTL on an explicit-TTL source stays explicit.
	txt := read(t, p)["13"]

	moved, err := p.UpdateRecord(context.Background(), testZone, txt, dnsprovider.Record{Type: "CAA", Name: "@", Value: `0 issue "ca.example.net"`, TTL: 3600})
	if err != nil {
		t.Fatal(err)
	}

	if w := f.zone().staged[mustID(t, moved.ID)]; w.TTL != 3600 {
		t.Fatalf("explicit TTL became inherited: %+v", w)
	}
}

func TestTypeMovePrechecksCollisions(t *testing.T) {
	f := writeFake(t)
	p := f.provider(t)
	before := read(t, p)["11"]

	after := dnsprovider.Record{Type: "TXT", Name: "example.com", Value: `"hello"`, TTL: 300}
	if _, err := p.UpdateRecord(context.Background(), testZone, before, after); !errors.Is(err, dnsprovider.ErrConflict) {
		t.Fatalf("move collision = %v", err)
	}

	if len(f.mutations()) != 0 {
		t.Fatalf("mutations = %v", f.mutations())
	}
}

func TestPartialTypeMoveIsReportedAndPublishedHonestly(t *testing.T) {
	f := writeFake(t)
	f.fail["DELETE /domain/zone/example.com/record/11"] = []int{http.StatusForbidden}
	p := f.provider(t)
	before := read(t, p)["11"]

	_, err := p.UpdateRecord(context.Background(), testZone, before, dnsprovider.Record{Type: "AAAA", Name: "www", Value: "2001:db8::1", TTL: 300})
	if err == nil || !strings.Contains(err.Error(), "partially") || !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("partial move = %v", err)
	}

	m := f.mutations()
	if countPrefix(m, "POST /domain/zone/example.com/record") != 1 || countPrefix(m, "POST /domain/zone/example.com/refresh") != 1 {
		t.Fatalf("mutations = %v", m)
	}

	if _, ok := f.published("11"); !ok {
		t.Fatal("the old Record was lost")
	}
}

func TestApplyStagesAllThenRefreshesOnce(t *testing.T) {
	f := writeFake(t)
	f.rejectTarget = "192.0.2.66"
	p := f.provider(t)
	rs := read(t, p)

	modified := rs["13"]
	modified.Value = `"changed"`

	cs := dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "new", Value: "192.0.2.5", TTL: 300}},
		{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "bad", Value: "192.0.2.66", TTL: 300}},
		{Kind: dnsprovider.ChangeModify, Before: rs["13"], After: modified},
		{Kind: dnsprovider.ChangeDelete, Before: rs["12"]},
	}}

	res, err := dnsprovider.Apply(context.Background(), p, cs)
	if err != nil {
		t.Fatal(err)
	}

	if res.Results[0].Err != nil || res.Results[0].Record.Name != "new.example.com" || res.Results[1].Err == nil || res.Results[2].Err != nil || res.Results[2].Record.Value != `"changed"` || res.Results[3].Err != nil {
		t.Fatalf("results = %+v", res.Results)
	}

	for i, r := range res.Results {
		if r.Change.Kind != cs.Changes[i].Kind {
			t.Fatalf("result %d out of order", i)
		}
	}

	m := f.mutations()
	if m[0] != "DELETE /domain/zone/example.com/record/12" || m[1] != "PUT /domain/zone/example.com/record/13" || m[len(m)-1] != "POST /domain/zone/example.com/refresh" || countPrefix(m, "POST /domain/zone/example.com/refresh") != 1 {
		t.Fatalf("mutations = %v", m)
	}

	if _, ok := f.published(res.Results[0].Record.ID); !ok {
		t.Fatal("a successful edit was not published beside a failed one")
	}

	if _, ok := f.published("12"); ok {
		t.Fatal("deletion not published")
	}
}

func TestApplyTypeMoveInsideABatchKeepsOrderAndResults(t *testing.T) {
	f := writeFake(t)
	p := f.provider(t)
	rs := read(t, p)

	cs := dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "www", Value: "192.0.2.9", TTL: 300}},
		{Kind: dnsprovider.ChangeModify, Before: rs["11"], After: dnsprovider.Record{Type: "AAAA", Name: "www", Value: "2001:db8::1", TTL: 3600}},
		{Kind: dnsprovider.ChangeDelete, Before: rs["12"]},
	}}

	res, err := dnsprovider.Apply(context.Background(), p, cs)
	if err != nil {
		t.Fatal(err)
	}

	for i, r := range res.Results {
		if r.Err != nil || r.Change.Kind != cs.Changes[i].Kind {
			t.Fatalf("result %d = %+v", i, r)
		}
	}

	added, moved := res.Results[0].Record, res.Results[1].Record
	if added.Type != "A" || added.Value != "192.0.2.9" || moved.Type != "AAAA" || moved.Value != "2001:db8::1" || moved.ID == "11" || res.Results[2].Record.ID != "" {
		t.Fatalf("results = %+v", res.Results)
	}

	want := []string{
		"DELETE /domain/zone/example.com/record/12",
		"POST /domain/zone/example.com/record",
		"DELETE /domain/zone/example.com/record/11",
		"POST /domain/zone/example.com/record",
		"POST /domain/zone/example.com/refresh",
	}
	if !slices.Equal(f.mutations(), want) {
		t.Fatalf("mutations = %v, want %v", f.mutations(), want)
	}

	got := read(t, p)
	if _, ok := got["11"]; ok || got[moved.ID].Type != "AAAA" || got[added.ID].Value != "192.0.2.9" || len(got) != 3 {
		t.Fatalf("stored = %+v", got)
	}
}

func TestApplyReportsTheSerialAfterRefresh(t *testing.T) {
	f := writeFake(t)
	p := f.provider(t)

	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "new", Value: "192.0.2.5", TTL: 300}},
	}})
	if err != nil || res.Serial != 2026101002 {
		t.Fatalf("Apply = serial %d, %v; want the refreshed SOA serial", res.Serial, err)
	}

	// Nothing staged: the serial read before is still the Zone's.
	res, err = dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "new", Value: "192.0.2.5", TTL: 300}},
	}})
	if err != nil || res.Serial != 2026101002 || !errors.Is(res.Results[0].Err, dnsprovider.ErrConflict) {
		t.Fatalf("unchanged Apply = %+v, %v", res, err)
	}
}

func TestApplyWithoutStagedEditsDoesNotRefresh(t *testing.T) {
	f := writeFake(t)
	f.rejectTarget = "192.0.2.66"
	p := f.provider(t)
	rs := read(t, p)

	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: testZone})
	if err != nil || len(res.Results) != 0 {
		t.Fatalf("empty = %+v, %v", res, err)
	}

	res, err = dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "bad", Value: "192.0.2.66", TTL: 300}},
		{Kind: dnsprovider.ChangeAdd, After: rs["11"]},
	}})
	if err != nil || res.Results[0].Err == nil || !errors.Is(res.Results[1].Err, dnsprovider.ErrConflict) {
		t.Fatalf("all failed = %+v, %v", res, err)
	}

	stale := rs["11"]
	stale.Value = "192.0.2.200"

	_, err = dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "fine", Value: "192.0.2.7", TTL: 300}},
		{Kind: dnsprovider.ChangeDelete, Before: stale},
	}})
	if !errors.Is(err, dnsprovider.ErrStale) {
		t.Fatalf("stale = %v", err)
	}

	if countPrefix(f.mutations(), "POST /domain/zone/example.com/refresh") != 0 || countPrefix(f.mutations(), "POST /domain/zone/example.com/record") != 1 {
		t.Fatalf("mutations = %v", f.mutations())
	}
}

func TestRefreshFailureKeepsStagingErrorsAndMarksStagedUnpublished(t *testing.T) {
	f := writeFake(t)
	f.rejectTarget = "192.0.2.66"
	f.fail["POST /domain/zone/example.com/refresh"] = []int{http.StatusInternalServerError}
	p := f.provider(t)
	rs := read(t, p)

	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "new", Value: "192.0.2.5", TTL: 300}},
		{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "bad", Value: "192.0.2.66", TTL: 300}},
		{Kind: dnsprovider.ChangeDelete, Before: rs["12"]},
	}})
	if !errors.Is(err, ovhcloud.ErrUnpublished) || len(res.Results) != 3 {
		t.Fatalf("Apply = %+v, %v", res, err)
	}

	for _, i := range []int{0, 2} {
		if !errors.Is(res.Results[i].Err, ovhcloud.ErrUnpublished) || res.Results[i].Record.ID != "" {
			t.Errorf("staged result %d = %+v", i, res.Results[i])
		}
	}

	if errors.Is(res.Results[1].Err, ovhcloud.ErrUnpublished) || res.Results[1].Err == nil || !strings.Contains(res.Results[1].Err.Error(), "Invalid target") {
		t.Errorf("staging failure replaced: %v", res.Results[1].Err)
	}

	m := f.mutations()
	if countPrefix(m, "POST /domain/zone/example.com/refresh") != 1 || countPrefix(m, "POST /domain/zone/example.com/record") != 2 || countPrefix(m, "DELETE") != 1 {
		t.Fatalf("rollback, retry or resubmission: %v", m)
	}

	if _, ok := f.published("12"); !ok {
		t.Fatal("unpublished deletion reported as published")
	}

	// Single CRUD reports the unconfirmed publication too.
	f.fail["POST /domain/zone/example.com/refresh"] = []int{http.StatusServiceUnavailable}
	if _, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "A", Name: "single", Value: "192.0.2.8", TTL: 300}); !errors.Is(err, ovhcloud.ErrUnpublished) {
		t.Fatalf("single = %v", err)
	}
}

func TestLostCreateResponseIsNotResubmitted(t *testing.T) {
	f := writeFake(t)
	f.lose["POST /domain/zone/example.com/record"] = true
	p := f.provider(t)

	_, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "A", Name: "new", Value: "192.0.2.5", TTL: 300})
	if err == nil || !strings.Contains(err.Error(), "unconfirmed") {
		t.Fatalf("lost create = %v", err)
	}

	if countPrefix(f.mutations(), "POST /domain/zone/example.com/record") != 1 {
		t.Fatalf("resubmitted: %v", f.mutations())
	}
}

func TestFailedReadBackReportsPossibleSideEffects(t *testing.T) {
	f := writeFake(t)
	p := f.provider(t)
	rs := read(t, p)

	// The write's own snapshot reads it; the read-back after PUT fails.
	f.fail["GET /domain/zone/example.com/record/11"] = []int{0, http.StatusForbidden}
	after := rs["11"]
	after.Value = "192.0.2.4"

	_, err := p.UpdateRecord(context.Background(), testZone, rs["11"], after)
	if err == nil || !strings.Contains(err.Error(), "staged") {
		t.Fatalf("read-back failure = %v", err)
	}

	if countPrefix(f.mutations(), "PUT") != 1 {
		t.Fatalf("write repeated: %v", f.mutations())
	}
}

func TestTXTNormalizedByTheServiceIsReturnedAsStored(t *testing.T) {
	f := writeFake(t)
	f.normalizeTXT = true
	p := f.provider(t)

	stored, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "TXT", Name: "txt", Value: "plain text", TTL: 300})
	if err != nil || stored.Value != `"plain text"` {
		t.Fatalf("stored = %+v, %v", stored, err)
	}

	if f.zone().staged[mustID(t, stored.ID)].Target != "plain text" {
		t.Fatal("fixture did not normalize")
	}
}

func TestWritesRoundTripStructuredValues(t *testing.T) {
	for _, tc := range []struct {
		typ, name             string
		create, update        string
		wireCreate, stored    string
		wireUpdate, reUpdated string
	}{
		{
			typ: "MX", name: "@",
			create: "010 Mail.Example.com", wireCreate: "10 mail.example.com.", stored: "10 mail.example.com.",
			update: "20 mx.example.net.", wireUpdate: "20 mx.example.net.", reUpdated: "20 mx.example.net.",
		},
		{
			typ: "SRV", name: "_sip._tcp",
			create: "10 5 5060 SIP.example.com", wireCreate: "10 5 5060 sip.example.com.", stored: "10 5 5060 sip.example.com.",
			update: "20 10 5061 sips.example.net.", wireUpdate: "20 10 5061 sips.example.net.", reUpdated: "20 10 5061 sips.example.net.",
		},
		{
			typ: "CAA", name: "@",
			create: `0 issue "letsencrypt.org"`, wireCreate: `0 issue "letsencrypt.org"`, stored: `0 issue "letsencrypt.org"`,
			update: `128 iodef "mailto:security@example.com"`, wireUpdate: `128 iodef "mailto:security@example.com"`, reUpdated: `128 iodef "mailto:security@example.com"`,
		},
		{
			typ: "TXT", name: "txt",
			create: "v=spf1 -all", wireCreate: `"v=spf1 -all"`, stored: `"v=spf1 -all"`,
			update: `"one" "two"`, wireUpdate: `"one" "two"`, reUpdated: `"one" "two"`,
		},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			f := writeFake(t)
			p := f.provider(t)

			created, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: tc.typ, Name: tc.name, Value: tc.create, TTL: 600})
			if err != nil || created.Value != tc.stored {
				t.Fatalf("created = %+v, %v; want %q", created, err, tc.stored)
			}

			if w, _ := f.published(created.ID); w.Target != tc.wireCreate || w.FieldType != tc.typ {
				t.Fatalf("stored target %q, want %q", w.Target, tc.wireCreate)
			}

			if got := read(t, p)[created.ID]; got.Value != tc.stored {
				t.Fatalf("read back %q, want %q", got.Value, tc.stored)
			}

			after := created
			after.Value = tc.update

			updated, err := p.UpdateRecord(context.Background(), testZone, created, after)
			if err != nil || updated.ID != created.ID || updated.Value != tc.reUpdated {
				t.Fatalf("updated = %+v, %v; want %q", updated, err, tc.reUpdated)
			}

			if w, _ := f.published(created.ID); w.Target != tc.wireUpdate {
				t.Fatalf("updated target %q, want %q", w.Target, tc.wireUpdate)
			}

			if got := read(t, p)[created.ID]; got.Value != tc.reUpdated {
				t.Fatalf("read back %q, want %q", got.Value, tc.reUpdated)
			}
		})
	}
}

func mustID(t *testing.T, id string) int64 {
	t.Helper()

	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		t.Fatal(err)
	}

	return n
}

func TestNativeErrorsMapToSentinels(t *testing.T) {
	for _, tc := range []struct {
		status int
		kind   error
	}{
		{http.StatusForbidden, dnsprovider.ErrUnauthorized},
		{http.StatusNotFound, dnsprovider.ErrNotFound},
		{http.StatusConflict, dnsprovider.ErrConflict},
		{http.StatusTooManyRequests, dnsprovider.ErrRateLimited},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			f := writeFake(t)
			f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/domain/zone" {
					w.Header().Set("Retry-After", "60")
					w.Header().Set("X-Ovh-Queryid", "EU.query")
					w.WriteHeader(tc.status)
					_ = json.NewEncoder(w).Encode(map[string]any{"class": classOf(tc.status), "message": "denied " + consumerKey, "details": map[string]string{"unauthorizedActionsByIAM": "dnsZone:apiovh:get"}})

					return
				}

				f.serve(w, r)
			})

			_, err := f.provider(t).Zones(context.Background(), dnsprovider.ZoneFilter{})

			var api *dnsprovider.APIError
			if !errors.Is(err, tc.kind) || !errors.As(err, &api) || api.StatusCode != tc.status || strings.Contains(err.Error(), consumerKey) || !strings.Contains(err.Error(), "dnsZone:apiovh:get") {
				t.Fatalf("error = %v", err)
			}

			if tc.status == http.StatusTooManyRequests && api.RetryAfter != time.Minute {
				t.Fatalf("RetryAfter = %v", api.RetryAfter)
			}
		})
	}
}

func TestRefreshFailureAlsoMarksPossiblyStagedFailures(t *testing.T) {
	f := writeFake(t)
	f.fail["POST /domain/zone/example.com/refresh"] = []int{http.StatusInternalServerError}
	// The test read, Apply's stale check and the snapshot read 11; the
	// read-back after its PUT fails.
	f.fail["GET /domain/zone/example.com/record/11"] = []int{0, 0, 0, http.StatusForbidden}
	f.fail["DELETE /domain/zone/example.com/record/12"] = []int{http.StatusForbidden}
	p := f.provider(t)
	rs := read(t, p)

	f.mu.Lock()
	f.lose["POST /domain/zone/example.com/record"] = true
	f.mu.Unlock()

	modified := rs["11"]
	modified.Value = "192.0.2.4"

	// Apply's order: modifications, then additions. The move's create is
	// the first POST, so the lost answer is the move's; the addition is
	// confirmed staged.
	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeModify, Before: rs["11"], After: modified},
		{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "fine", Value: "192.0.2.5", TTL: 300}},
		{Kind: dnsprovider.ChangeModify, Before: rs["12"], After: dnsprovider.Record{Type: "AAAA", Name: "www", Value: "2001:db8::1", TTL: 300}},
	}})
	if !errors.Is(err, ovhcloud.ErrUnpublished) || len(res.Results) != 3 {
		t.Fatalf("Apply = %+v, %v", res, err)
	}

	for i, want := range []string{"read back", "", "unconfirmed"} {
		got := res.Results[i].Err
		if !errors.Is(got, ovhcloud.ErrUnpublished) || !strings.Contains(got.Error(), want) || res.Results[i].Record.ID != "" {
			t.Errorf("result %d = %+v, want ErrUnpublished joined with %q", i, res.Results[i], want)
		}
	}

	if !errors.Is(res.Results[0].Err, dnsprovider.ErrUnauthorized) {
		t.Errorf("read-back failure lost its cause: %v", res.Results[0].Err)
	}
}

func TestRefreshFailureMarksPartialTypeMove(t *testing.T) {
	f := writeFake(t)
	f.fail["POST /domain/zone/example.com/refresh"] = []int{http.StatusInternalServerError}
	f.fail["DELETE /domain/zone/example.com/record/12"] = []int{http.StatusForbidden}
	p := f.provider(t)
	rs := read(t, p)

	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeModify, Before: rs["12"], After: dnsprovider.Record{Type: "AAAA", Name: "www", Value: "2001:db8::1", TTL: 300}},
	}})
	if !errors.Is(err, ovhcloud.ErrUnpublished) {
		t.Fatalf("Apply = %v", err)
	}

	got := res.Results[0].Err
	if !errors.Is(got, ovhcloud.ErrUnpublished) || !errors.Is(got, dnsprovider.ErrUnauthorized) || !strings.Contains(got.Error(), "partially staged") {
		t.Fatalf("partial move = %v", got)
	}
}
