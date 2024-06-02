# Resolver

A pure Go DNS resolver implementation, designed to be a drop in replacement for 
[net.Resolver](https://pkg.go.dev/net#Resolver).

## Features

* Pure Go implementation.
* DNS over UDP, TCP, and TLS.
* Fluent and expressive API (allowing sophisticated resolution strategies).
* Parallel query support.
* Custom dialer support.

## TODOs

* [ ] Support for `/etc/resolvers/` see: [Go #12524](https://github.com/golang/go/issues/12524), might make sense to shell out to `scutil --dns`.
* [ ] DNS over HTTPS support.
* [ ] DNSSEC support?
* [ ] Multicast DNS support, RFC 6762?
* [ ] Non recursive DNS server support?