package rest_test

import (
	"errors"
	"slices"
	"strconv"
	"testing"

	"github.com/dnsgateway/dnsprovider/rest"
)

// items are seven things, "a" to "g", served in pages.
var items = []string{"a", "b", "c", "d", "e", "f", "g"}

// from serves size items from start.
func from(start, size int) []string {
	start = min(start, len(items))

	return items[start:min(start+size, len(items))]
}

func TestPagesReadsEveryStyle(t *testing.T) {
	cases := []struct {
		name   string
		marker func(string) string
		fetch  func(p rest.Page) ([]string, error)
	}{
		{"offset", nil, func(p rest.Page) ([]string, error) { return from(p.Offset, p.Size), nil }},
		{"page", nil, func(p rest.Page) ([]string, error) { return from((p.Number-1)*p.Size, p.Size), nil }},
		{"marker", func(s string) string { return s }, func(p rest.Page) ([]string, error) {
			return from(slices.Index(items, p.Marker)+1, p.Size), nil
		}},
	}

	for _, c := range cases {
		for _, size := range []int{1, 3, 7, 10} {
			t.Run(c.name+" "+strconv.Itoa(size), func(t *testing.T) {
				var asked []rest.Page

				got, err := rest.Pages(size, c.marker, func(p rest.Page) ([]string, error) {
					asked = append(asked, p)

					return c.fetch(p)
				})
				if err != nil {
					t.Fatalf("Pages: %v", err)
				}

				if !slices.Equal(got, items) {
					t.Errorf("Pages = %v, want %v", got, items)
				}

				// Seven items: a short page ends the list, else one more
				// (empty) page is asked for.
				if want := len(items)/size + 1; len(asked) != want {
					t.Errorf("asked for %d pages, want %d", len(asked), want)
				}
			})
		}
	}
}

func TestPagesAsksForEachPageInTurn(t *testing.T) {
	var asked []rest.Page

	_, err := rest.Pages(3, func(s string) string { return s }, func(p rest.Page) ([]string, error) {
		asked = append(asked, p)

		return from(p.Offset, p.Size), nil
	})
	if err != nil {
		t.Fatalf("Pages: %v", err)
	}

	want := []rest.Page{
		{Number: 1, Offset: 0, Marker: "", Size: 3},
		{Number: 2, Offset: 3, Marker: "c", Size: 3},
		{Number: 3, Offset: 6, Marker: "f", Size: 3},
	}
	if !slices.Equal(asked, want) {
		t.Errorf("asked for %+v, want %+v", asked, want)
	}
}

func TestPagesRefusesTheSamePageTwice(t *testing.T) {
	_, err := rest.Pages(2, nil, func(rest.Page) ([]string, error) { return from(0, 2), nil })
	if !errors.Is(err, rest.ErrSamePage) {
		t.Errorf("err = %v, want ErrSamePage: an API that ignores paging would loop forever", err)
	}
}

func TestPagesStopsAtAFetchError(t *testing.T) {
	boom := errors.New("boom")

	got, err := rest.Pages(2, nil, func(p rest.Page) ([]string, error) {
		if p.Number == 2 {
			return nil, boom
		}

		return from(p.Offset, p.Size), nil
	})
	if !errors.Is(err, boom) || got != nil {
		t.Errorf("Pages = %v, %v, want no items and the fetch error", got, err)
	}
}
