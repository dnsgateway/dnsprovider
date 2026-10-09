package gandi_test

import (
	"context"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

func TestTXTDecimalEscapesRetainPresentationAndSiblings(t *testing.T) {
	f, p := newService(t, map[string]any{"rrset_name": "@", "rrset_type": "TXT", "rrset_ttl": 300, "rrset_values": []string{`"\065"`, `"one" "two"`, `"ordinary"`}})
	before := read(t, p)
	if before[0].Value != "A" || before[1].Value != `"one" "two"` || before[2].Value != "ordinary" {
		t.Fatalf("TXT = %+v", before)
	}
	after := before[2]
	after.Value = `a "quote" and a \ slash`
	got, err := p.UpdateRecord(context.Background(), testZone, before[2], after)
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != after.Value {
		t.Fatalf("roundtrip = %q, want %q", got.Value, after.Value)
	}
	raw := f.sets["@/TXT"]["rrset_values"].([]any)
	if raw[0] != `"\065"` || raw[1] != `"one" "two"` {
		t.Fatalf("sibling presentation changed: %v", raw)
	}
}

func TestQuotedSingleTXTCreateTreatsQuotesAndEscapesAsLiteralText(t *testing.T) {
	_, p := newService(t)
	got, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Name: "@", Type: "TXT", Value: `"hello\032world"`, TTL: 300})
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != `"hello\032world"` {
		t.Fatalf("stored TXT = %q", got.Value)
	}
}

func TestTXTQuotedLiteralTTLChangePreservesExactWire(t *testing.T) {
	f, p := newService(t, map[string]any{"rrset_name": "@", "rrset_type": "TXT", "rrset_ttl": 300, "rrset_values": []string{`"\"hello\""`, `"one" "two"`, `"\065"`}})
	before := read(t, p)
	if before[0].Value != `"hello"` {
		t.Fatalf("literal quote content = %q", before[0].Value)
	}
	changes := make([]dnsprovider.Change, 0, len(before))
	for _, r := range before {
		after := r
		after.TTL = 600
		changes = append(changes, dnsprovider.Change{Kind: dnsprovider.ChangeModify, Before: r, After: after})
	}
	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: testZone, Changes: changes})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res.Results {
		if r.Err != nil || r.Record.TTL != 600 {
			t.Fatalf("TTL edit = %+v", res)
		}
	}
	after := read(t, p)
	if after[0].Value != `"hello"` || after[1].Value != `"one" "two"` || after[2].Value != "A" {
		t.Fatalf("TXT content changed = %+v", after)
	}
	wire := f.sets["@/TXT"]["rrset_values"].([]any)
	if wire[0] != `"\"hello\""` || wire[1] != `"one" "two"` || wire[2] != `"\065"` {
		t.Fatalf("wire changed = %v", wire)
	}
}

func TestTXTUnmatchedLeadingQuoteCreateUsesLiteralContract(t *testing.T) {
	f, p := newService(t)
	got, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Name: "@", Type: "TXT", Value: `"hello`, TTL: 300})
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != `"hello` {
		t.Fatalf("stored content = %q", got.Value)
	}
	wire := f.sets["@/TXT"]["rrset_values"].([]any)
	if wire[0] != `"\"hello"` {
		t.Fatalf("invalid TXT presentation = %v", wire)
	}
}
