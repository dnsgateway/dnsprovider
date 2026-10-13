package readback_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/readback"
)

func txt(value string, ttl uint32) dnsprovider.Record {
	return dnsprovider.Record{Type: "TXT", Name: "_acme-challenge.example.com", Value: value, TTL: ttl}
}

func withID(r dnsprovider.Record) dnsprovider.Record {
	r.ID = "id-" + r.Value

	return r
}

func TestVerifyReturnsTheAddedRecordsAsHeld(t *testing.T) {
	e := readback.Effects{Added: []dnsprovider.Record{txt("a", 300), {}}}
	held := []dnsprovider.Record{withID(txt("a", 300))}

	got, err := readback.Verify(e, held, dnsprovider.SameRecord)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if want := []dnsprovider.Record{withID(txt("a", 300)), {}}; !reflect.DeepEqual(got, want) {
		t.Errorf("Verify = %+v, want %+v", got, want)
	}
}

func TestVerifyIgnoresRecordsTheChangesetDidNotTouch(t *testing.T) {
	e := readback.Effects{
		Added:   []dnsprovider.Record{txt("a", 300)},
		Removed: []readback.Removal{{Record: txt("old", 300)}},
	}
	// Another writer added "b" and changed "c" meanwhile.
	held := []dnsprovider.Record{txt("b", 300), txt("a", 300), txt("c", 60)}

	if _, err := readback.Verify(e, held, dnsprovider.SameRecord); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestVerifyIsAConflictWhenAnAddedRecordIsNotHeldAsWritten(t *testing.T) {
	for name, held := range map[string][]dnsprovider.Record{
		"missing":       {txt("b", 300)},
		"another TTL":   {txt("a", 60)},
		"nothing held":  nil,
		"in another RR": {{Type: "TXT", Name: "other.example.com", Value: "a", TTL: 300}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := readback.Verify(readback.Effects{Added: []dnsprovider.Record{txt("a", 300)}}, held, dnsprovider.SameRecord)
			if !errors.Is(err, dnsprovider.ErrConflict) {
				t.Errorf("Verify = %v, want ErrConflict", err)
			}
		})
	}
}

func TestVerifyIsAConflictWhenARemovedRecordIsHeldMoreOftenThanLeft(t *testing.T) {
	for _, c := range []struct {
		name  string
		leave int
		held  []dnsprovider.Record
		fails bool
	}{
		{"gone", 0, nil, false},
		{"still held", 0, []dnsprovider.Record{txt("old", 300)}, true},
		{"still held, another TTL", 0, []dnsprovider.Record{txt("old", 60)}, true},
		{"one of two left", 1, []dnsprovider.Record{txt("old", 300)}, false},
		{"both of two left", 1, []dnsprovider.Record{txt("old", 300), txt("old", 600)}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := readback.Effects{Removed: []readback.Removal{{Record: txt("old", 300), Leave: c.leave}}}

			_, err := readback.Verify(e, c.held, dnsprovider.SameRecord)
			if got := errors.Is(err, dnsprovider.ErrConflict); got != c.fails {
				t.Errorf("Verify = %v, want a conflict: %v", err, c.fails)
			}
		})
	}
}

func TestVerifyComparesWithTheGivenIdentity(t *testing.T) {
	// A Provider that reads values back in another form tells resource
	// records apart its own way.
	caseless := func(a, b dnsprovider.Record) bool {
		return a.Type == b.Type && a.Name == b.Name && strings.EqualFold(a.Value, b.Value)
	}

	e := readback.Effects{Added: []dnsprovider.Record{txt("A", 300)}}
	if _, err := readback.Verify(e, []dnsprovider.Record{txt("a", 300)}, caseless); err != nil {
		t.Errorf("Verify: %v", err)
	}
}
