package dnsprovider_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

func TestUnconfirmedLeavesAWriteTheProviderRefused(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"4xx answer", &dnsprovider.APIError{Provider: "p", StatusCode: 409}, false},
		{"error inside a successful answer", &dnsprovider.APIError{Provider: "p", Messages: []string{"bad"}}, false},
		{"wrapped 4xx answer", fmt.Errorf("p: create: %w", &dnsprovider.APIError{StatusCode: 422}), false},
		{"5xx answer", &dnsprovider.APIError{Provider: "p", StatusCode: 502}, true},
		{"lost answer", context.DeadlineExceeded, true},
		{"malformed acknowledgement", errors.New("no ID"), true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := dnsprovider.Unconfirmed(c.err)
			if errors.Is(got, dnsprovider.ErrUnconfirmed) != c.want {
				t.Errorf("Unconfirmed(%v) = %v, matches ErrUnconfirmed %v, want %v", c.err, got, !c.want, c.want)
			}

			if c.err != nil && !errors.Is(got, c.err) {
				t.Errorf("Unconfirmed(%v) = %v, lost its cause", c.err, got)
			}
		})
	}
}

func TestUnconfirmedMarksOnce(t *testing.T) {
	once := dnsprovider.Unconfirmed(errors.New("lost"))
	if twice := dnsprovider.Unconfirmed(once); twice != once {
		t.Errorf("Unconfirmed twice = %v, want %v", twice, once)
	}
}
