package batch_test

import (
	"context"
	"errors"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/batch"
)

// noResults is a Batcher that answers without a result for the change.
type noResults struct{}

func (noResults) ApplyChangeset(context.Context, dnsprovider.Changeset) (dnsprovider.ApplyResult, error) {
	return dnsprovider.ApplyResult{}, nil
}

func TestAWriteTheBatcherGivesNoResultForFails(t *testing.T) {
	r := dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}

	if _, err := batch.Create(context.Background(), noResults{}, dnsprovider.Zone{}, r); err == nil {
		t.Error("Create succeeded without a result")
	}

	if err := batch.Delete(context.Background(), noResults{}, dnsprovider.Zone{}, r); err == nil {
		t.Error("Delete succeeded without a result")
	}
}

// failedBoth is a Batcher whose one change and the Changeset both fail.
type failedBoth struct{ change, changeset error }

func (b failedBoth) ApplyChangeset(_ context.Context, cs dnsprovider.Changeset) (dnsprovider.ApplyResult, error) {
	return dnsprovider.ApplyResult{Results: []dnsprovider.ChangeResult{{Change: cs.Changes[0], Err: b.change}}}, b.changeset
}

func TestAWriteReportsTheChangesOwnErrorBeforeTheChangesets(t *testing.T) {
	r := dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	own, whole := errors.New("own"), errors.New("whole")

	if _, err := batch.Create(context.Background(), failedBoth{own, whole}, dnsprovider.Zone{}, r); !errors.Is(err, own) {
		t.Errorf("Create = %v, want the change's own error", err)
	}

	if err := batch.Delete(context.Background(), failedBoth{nil, whole}, dnsprovider.Zone{}, r); !errors.Is(err, whole) {
		t.Errorf("Delete = %v, want the Changeset's error", err)
	}
}
