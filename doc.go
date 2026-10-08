// Package dnsprovider manages DNS hosting at DNS Providers through one
// interface: the Provider, with its lean, provider-neutral Zone and Record
// types, the record rules every consumer needs to build valid Records, and
// the Changeset applied to a Zone as one operation.
//
// Adapters live in the providers/ packages; providertest holds a fake
// Provider for consumers' tests.
package dnsprovider
