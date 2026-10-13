// Package readback checks a Changeset's own effects in the Records a
// Provider holds after a write. Another writer may change the same Zone
// at the same time, so only what the Changeset itself added and removed
// is compared: Records it did not touch may differ from what it read.
package readback

import (
	"fmt"

	"github.com/dnsgateway/dnsprovider"
)

// Effects are what a Changeset must have left at the Provider.
type Effects struct {
	// Added are the Records the Changeset adds or modifies into, by
	// change; a Record of no Type for a change that adds none. Each must
	// be held with its TTL.
	Added []dnsprovider.Record
	// Removed are the resource records the Changeset deletes or modifies
	// away.
	Removed []Removal
}

// Removal is a resource record a Changeset removes, and how many times
// it leaves it at the Provider: none, unless the Provider holds it more
// than once or the Changeset adds it back.
type Removal struct {
	Record dnsprovider.Record
	Leave  int
}

// Verify checks a Changeset's Effects against held, the Records read back
// after its write, with same telling resource records apart. It returns
// the held Record for each of Added, by change: the Record as the
// Provider holds it, with its ID. An added Record not held with its TTL,
// or a removed one held more often than it leaves it, is an error that
// matches dnsprovider.ErrConflict: another write replaced the Changeset's.
func Verify(e Effects, held []dnsprovider.Record, same func(a, b dnsprovider.Record) bool) ([]dnsprovider.Record, error) {
	stored := make([]dnsprovider.Record, len(e.Added))

	for i, want := range e.Added {
		if want.Type == "" {
			continue
		}

		at := -1

		for j, r := range held {
			if same(want, r) && r.TTL == want.TTL {
				at = j

				break
			}
		}

		if at < 0 {
			return nil, fmt.Errorf("%s is not held as written: %w", describe(want), dnsprovider.ErrConflict)
		}

		stored[i] = held[at]
	}

	for _, rm := range e.Removed {
		n := 0

		for _, r := range held {
			if same(rm.Record, r) {
				n++
			}
		}

		if n > rm.Leave {
			return nil, fmt.Errorf("%s is held %d times, removed to %d: %w", describe(rm.Record), n, rm.Leave, dnsprovider.ErrConflict)
		}
	}

	return stored, nil
}

func describe(r dnsprovider.Record) string {
	return fmt.Sprintf("%s %s %q (TTL %d)", r.Type, r.Name, r.Value, r.TTL)
}
