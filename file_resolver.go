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

	"github.com/miekg/dns"
	"github.com/noisysockets/netutil/addrselect"
	"github.com/noisysockets/netutil/hostsfile"
	"github.com/noisysockets/resolver/util"
)

var (
	_ Resolver = (*fileResolver)(nil)
)

// FileResolverConfig is the configuration for a hosts file resolver.
type FileResolverConfig struct {
	// DialContext is an optional function for creating network connections.
	// It is used for ordering the returned addresses.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

// fileResolver is a resolver that looks up names and numbers from a hosts file.
type fileResolver struct {
	addrsByName map[string][]netip.Addr
	namesByAddr map[netip.Addr][]string
	dialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

// File creates a new hosts file resolver from the given reader.
func File(hostsfileReader io.Reader, conf *FileResolverConfig) (*fileResolver, error) {
	if conf == nil {
		conf = &FileResolverConfig{}
	}

	h, err := hostsfile.Decode(hostsfileReader)
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

	return &fileResolver{
		addrsByName: addrsByName,
		namesByAddr: namesByAddr,
		dialContext: conf.DialContext,
	}, nil
}

func (r *fileResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	addrs, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	return util.Strings(addrs), nil
}

func (r *fileResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	dnsErr := &net.DNSError{
		Name: host,
	}

	allAddrs, ok := r.addrsByName[dns.Fqdn(host)]
	if !ok {
		return nil, extendDNSError(dnsErr, net.DNSError{
			Err:        ErrNoSuchHost.Error(),
			IsNotFound: true,
		})
	}

	if network != "ip" && network != "ip4" && network != "ip6" {
		return nil, extendDNSError(dnsErr, net.DNSError{
			Err: ErrUnsupportedNetwork.Error(),
		})
	}

	addrs, err := util.FilterAddresses(allAddrs, network)
	if err != nil {
		return nil, extendDNSError(dnsErr, net.DNSError{
			Err: err.Error(),
		})
	}

	if r.dialContext != nil {
		dial := func(network, address string) (net.Conn, error) {
			return r.dialContext(ctx, network, address)
		}

		addrselect.SortByRFC6724(dial, addrs)
	}

	return addrs, nil
}
