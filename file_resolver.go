// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package resolver

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"

	hostsfile "github.com/kevinburke/hostsfile/lib"
	"github.com/miekg/dns"
	"github.com/noisysockets/resolver/internal/addrselect"
	"github.com/noisysockets/resolver/internal/util"
)

var (
	_ Resolver = (*fileResolver)(nil)
)

// FileResolverConfig is the configuration for a hosts file resolver.
type FileResolverConfig struct {
	// DialContext is an optional function for creating network connections.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

// fileResolver is a resolver that looks up names and numbers from a hosts file.
type fileResolver struct {
	addrsByName map[string][]netip.Addr
	namesByAddr map[netip.Addr][]string
	dialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

// File creates a new hosts file resolver from the given reader.
func File(r io.Reader, conf *FileResolverConfig) (*fileResolver, error) {
	if conf == nil {
		conf = &FileResolverConfig{}
	}

	h, err := hostsfile.Decode(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse hosts file: %w", err)
	}

	addrsByName := make(map[string][]netip.Addr)
	namesByAddr := make(map[netip.Addr][]string)

	for _, record := range h.Records() {
		for name := range record.Hostnames {
			name = dns.Fqdn(name)

			addr, err := netip.ParseAddr(record.IpAddress.String())
			if err != nil {
				return nil, fmt.Errorf("failed to parse IP address: %w", err)
			}

			addrsByName[name] = append(addrsByName[name], addr)
			namesByAddr[addr] = append(namesByAddr[addr], name)
		}
	}

	dialContext := (&net.Dialer{}).DialContext
	if conf.DialContext != nil {
		dialContext = conf.DialContext
	}

	return &fileResolver{
		addrsByName: addrsByName,
		namesByAddr: namesByAddr,
		dialContext: dialContext,
	}, nil
}

// LookupHost looks up the given host using the resolver. It returns a slice of
// that host's addresses.
func (r *fileResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	addrs, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	return util.Strings(addrs), nil
}

// LookupNetIP looks up host using the resolver. It returns a slice of that
// host's IP addresses of the type specified by network. The network must be
// one of "ip", "ip4" or "ip6".
func (r *fileResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	allAddrs, ok := r.addrsByName[dns.Fqdn(host)]
	if !ok {
		return nil, &net.DNSError{
			Err:        ErrNoSuchHost.Error(),
			Name:       host,
			IsNotFound: true,
		}
	}

	var addrs []netip.Addr
	for _, addr := range allAddrs {
		switch network {
		case "ip":
			addrs = append(addrs, addr)
		case "ip4":
			if addr.Unmap().Is4() {
				addrs = append(addrs, addr)
			}
		case "ip6":
			if addr.Is6() {
				addrs = append(addrs, addr)
			}
		default:
			return nil, &net.DNSError{
				Err:  ErrUnsupportedNetwork.Error(),
				Name: host,
			}
		}
	}

	dial := func(network, address string) (net.Conn, error) {
		return r.dialContext(ctx, network, address)
	}

	addrselect.SortByRFC6724(dial, addrs)

	return addrs, nil
}
