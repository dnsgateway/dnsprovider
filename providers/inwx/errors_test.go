package inwx_test

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

func TestRefusalCodesMapToTheSharedErrors(t *testing.T) {
	for _, tc := range []struct {
		code int
		want error
	}{
		{2200, dnsprovider.ErrUnauthorized},
		{2201, dnsprovider.ErrUnauthorized},
		{2202, dnsprovider.ErrUnauthorized},
		{2302, dnsprovider.ErrConflict},
		{2303, dnsprovider.ErrNotFound},
		{2502, dnsprovider.ErrRateLimited},
	} {
		f := newFake(t)
		// An authentication code is resent once with a fresh session.
		f.scriptCode("account.info", tc.code, "SYNTHETIC: refused")
		f.scriptCode("account.info", tc.code, "SYNTHETIC: refused")

		_, err := f.provider().Account(context.Background())

		var api *dnsprovider.APIError
		if !errors.Is(err, tc.want) || !errors.As(err, &api) || api.StatusCode != 0 {
			t.Fatalf("code %d: Account = %v, want %v as an APIError", tc.code, err, tc.want)
		}
	}
}

func TestOtherRefusalsArePlainAPIErrorsCarryingCodeMessageAndReason(t *testing.T) {
	for _, code := range []int{2005, 2400} {
		f := newFake(t)
		f.scriptCode("account.info", code, "SYNTHETIC: the reason")

		_, err := f.provider().Account(context.Background())

		var api *dnsprovider.APIError
		if !errors.As(err, &api) {
			t.Fatalf("code %d: Account = %v, want an APIError", code, err)
		}

		for _, sentinel := range []error{dnsprovider.ErrUnauthorized, dnsprovider.ErrNotFound, dnsprovider.ErrConflict, dnsprovider.ErrRateLimited, dnsprovider.ErrUnconfirmed} {
			if errors.Is(err, sentinel) {
				t.Fatalf("code %d: %v matches %v", code, err, sentinel)
			}
		}

		for _, want := range []string{strconv.Itoa(code), messages[code], "SYNTHETIC: the reason"} {
			if !strings.Contains(strings.Join(api.Messages, "; "), want) || !strings.Contains(err.Error(), want) {
				t.Fatalf("code %d: %v (Messages %q) lacks %q", code, err, api.Messages, want)
			}
		}
	}
}

func TestHTTP429IsRateLimited(t *testing.T) {
	f := newFake(t)
	f.script("account.info", http.StatusTooManyRequests, "")

	_, err := f.provider().Account(context.Background())
	if !errors.Is(err, dnsprovider.ErrRateLimited) {
		t.Fatalf("Account = %v, want ErrRateLimited", err)
	}
}

func TestANon200AnswerIsAnAPIErrorOfItsStatus(t *testing.T) {
	f := newFake(t)
	f.script("account.info", http.StatusBadGateway, "<html>bad gateway</html>")

	_, err := f.provider().Account(context.Background())

	var api *dnsprovider.APIError
	if !errors.As(err, &api) || api.StatusCode != http.StatusBadGateway {
		t.Fatalf("Account = %v, want a 502 APIError", err)
	}

	if n := f.count("account.info"); n != 1 {
		t.Fatalf("sent account.info %d times, want 1", n)
	}
}

func TestALostOrUndecodableAnswerToAReadIsAnError(t *testing.T) {
	for _, rep := range []reply{{lost, ""}, {http.StatusOK, "not json"}, {http.StatusOK, `{"msg":"no code"}`}} {
		f := newFake(t)
		f.script("account.info", rep.status, rep.body)

		if _, err := f.provider().Account(context.Background()); err == nil {
			t.Fatalf("Account after %+v succeeded", rep)
		}
	}
}
