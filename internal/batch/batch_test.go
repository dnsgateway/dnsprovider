package batch_test

import (
	"context"
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
