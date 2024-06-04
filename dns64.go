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
	"net"
	"net/netip"

	"github.com/noisysockets/resolver/internal/addrselect"
	"github.com/noisysockets/resolver/internal/util"
)

var _ Resolver = (*dns64Resolver)(nil)

// DNS64ResolverConfig is the configuration for a DNS64 resolver.
type DNS64ResolverConfig struct {
	// Prefix is the IPv6 prefix to use.
	// If not set, the well-known prefix "64:ff9b::/96" is used.
	Prefix *netip.Prefix
	// DialContext is used to establish a connection to a DNS server.
	DialContext DialContextFunc
}

// dns64Resolver is a resolver that synthesizes IPv6 addresses from IPv4 addresses
// using DNS64 (RFC 6147).
type dns64Resolver struct {
	resolver    Resolver
	prefix      netip.Prefix
	dialContext DialContextFunc
}

// DNS64 returns a resolver that synthesizes IPv6 addresses from IPv4 addresses
// using DNS64 (RFC 6147).
func DNS64(resolver Resolver, conf *DNS64ResolverConfig) *dns64Resolver {
	conf, err := util.ConfigWithDefaults(conf, &DNS64ResolverConfig{
		Prefix:      util.PointerTo(netip.MustParsePrefix("64:ff9b::/96")),
		DialContext: (&net.Dialer{}).DialContext,
	})
	if err != nil {
		// Should never happen.
		panic(err)
	}

	return &dns64Resolver{
		resolver:    resolver,
		prefix:      *conf.Prefix,
		dialContext: conf.DialContext,
	}
}

func (r *dns64Resolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	addrs, err := r.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	var ipv4Addrs, ipv6Addrs []netip.Addr
	for _, addr := range addrs {
		if addr.Unmap().Is4() {
			ipv4Addrs = append(ipv4Addrs, addr.Unmap())
		} else {
			ipv6Addrs = append(ipv6Addrs, addr)
		}
	}

	if network == "ip4" {
		return ipv4Addrs, nil
	}

	// Add synthesized IPv6 addresses (if no IPv6 addresses were present).
	if len(ipv6Addrs) == 0 {
		for _, addr := range ipv4Addrs {
			ipv6Addrs = append(ipv6Addrs, r.synthesizeAddr(addr))
		}
	}

	if network == "ip6" {
		addrs = ipv6Addrs
	} else {
		addrs = append(ipv4Addrs, ipv6Addrs...)
	}

	dial := func(network, address string) (net.Conn, error) {
		return r.dialContext(ctx, network, address)
	}

	addrselect.SortByRFC6724(dial, addrs)

	return addrs, nil
}

func (r *dns64Resolver) synthesizeAddr(addr netip.Addr) netip.Addr {
	addr = addr.Unmap()
	if !addr.Is4() {
		return addr
	}

	var ipv6Addr [16]byte
	copy(ipv6Addr[:], r.prefix.Addr().AsSlice()[:12])
	copy(ipv6Addr[12:], addr.AsSlice())

	return netip.AddrFrom16(ipv6Addr)
}
