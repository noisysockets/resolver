# getresolvd

A minimal pure Go DNS resolver implementation, designed to be a drop in 
replacement for [net.Resolver](https://pkg.go.dev/net#Resolver).

## Features

* Pure Go implementation.
* DNS over UDP, TCP, and TLS.

## TODOs

* [ ] Implement more of the `net.Resolver` interface.
* [ ] Add support for retries.