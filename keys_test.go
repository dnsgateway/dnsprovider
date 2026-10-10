package dnsprovider_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

// keyHost is a Provider whose API returns the keys it signs a Zone with,
// or err when set.
type keyHost struct {
	dnsprovider.Provider
	err error
}

func (h keyHost) SigningKeys(context.Context, dnsprovider.Zone) ([]dnsprovider.SigningKey, error) {
	if h.err != nil {
		return nil, h.err
	}

	return []dnsprovider.SigningKey{{
		DNSKEY: "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
		KeyTag: 2371,
		DS:     []string{"2371 13 2 1F987CC6583E92DF0890718C42A2BC8C04E5A60A1D3E1FC1D0C7826A4F47B4C1"},
	}}, nil
}

func TestCanReadKeysOnlyForAKeyReader(t *testing.T) {
	if dnsprovider.CanReadKeys(oneTenant{}) {
		t.Error("a Provider whose API returns no keys reads them")
	}

	if !dnsprovider.CanReadKeys(keyHost{}) {
		t.Error("a KeyReader does not read keys")
	}
}

func TestSigningKeysOfAProviderWithoutAReaderAreNone(t *testing.T) {
	got, err := dnsprovider.SigningKeysOf(context.Background(), oneTenant{}, dnsprovider.Zone{ID: "z1", Name: "example.com"})
	if err != nil {
		t.Fatal(err)
	}

	if got != nil {
		t.Errorf("SigningKeysOf = %+v, want none", got)
	}
}

func TestSigningKeysOfAReaderAreWhatItReads(t *testing.T) {
	got, err := dnsprovider.SigningKeysOf(context.Background(), keyHost{}, dnsprovider.Zone{ID: "z1", Name: "example.com"})
	if err != nil {
		t.Fatal(err)
	}

	want := []dnsprovider.SigningKey{{
		DNSKEY: "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
		KeyTag: 2371,
		DS:     []string{"2371 13 2 1F987CC6583E92DF0890718C42A2BC8C04E5A60A1D3E1FC1D0C7826A4F47B4C1"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SigningKeysOf = %+v, want %+v", got, want)
	}

	if _, err := dnsprovider.SigningKeysOf(context.Background(), keyHost{err: dnsprovider.ErrUnauthorized}, dnsprovider.Zone{ID: "z1"}); !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Errorf("SigningKeysOf error = %v, want ErrUnauthorized", err)
	}
}
