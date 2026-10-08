package rest

import (
	"errors"
	"reflect"
)

// ErrSamePage means a list answered the same page twice: the API ignored
// the paging, and reading on would never end.
var ErrSamePage = errors.New("the same page was answered twice")

// Page says which page of a list to fetch, in each style an API may page
// by: the page number, the offset or the marker. A fetch reads the one
// its API takes.
type Page struct {
	// Number is the page, from 1.
	Number int
	// Offset is how many items the pages before held.
	Offset int
	// Marker is the marker of the last item read, the item this page
	// starts after; empty on the first page or without a marker func.
	Marker string
	// Size is the number of items to ask for.
	Size int
}

// Pages reads every page of a list with fetch, size items at a time. A
// page shorter than size is the last. marker, if not nil, names the item
// a marker-paged API starts the next page after.
func Pages[T any](size int, marker func(T) string, fetch func(Page) ([]T, error)) ([]T, error) {
	var out, last []T

	p := Page{Number: 1, Size: size}

	for {
		items, err := fetch(p)
		if err != nil {
			return nil, err
		}

		if len(items) > 0 && reflect.DeepEqual(items, last) {
			return nil, ErrSamePage
		}

		out = append(out, items...)

		if len(items) < size {
			return out, nil
		}

		last = items
		p.Number++
		p.Offset += len(items)

		if marker != nil {
			next := marker(items[len(items)-1])
			if next == p.Marker {
				return nil, ErrSamePage
			}

			p.Marker = next
		}
	}
}
