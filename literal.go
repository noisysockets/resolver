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

	"github.com/miekg/dns"
	"github.com/noisysockets/util/address"
)

var _ Resolver = (*literalResolver)(nil)

// literalResolver is a resolver that resolves IP literals.
type literalResolver struct{}

// Literal returns a resolver that resolves IP literals.
func Literal() Resolver {
	return &literalResolver{}
}

func (r *literalResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	var addrs []netip.Addr

	// Let localhost be localhost, the draft failed to reach consensus but I'm
	// going to implement it anyway (to address some security concerns).
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-let-localhost-be-localhost
	if dns.Fqdn(host) == "localhost." {
		addrs = []netip.Addr{
			netip.IPv6Loopback(),
			netip.MustParseAddr("127.0.0.1"),
		}
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{addr}
	}

	if network != "ip" && network != "ip4" && network != "ip6" {
		return nil, &net.DNSError{
			Err:  ErrUnsupportedNetwork.Error(),
			Name: host,
		}
	}

	addrs = address.FilterByNetwork(addrs, network)
	if len(addrs) == 0 {
		return nil, &net.DNSError{
			Err:        ErrNoSuchHost.Error(),
			Name:       host,
			IsNotFound: true,
		}
	}

	return addrs, nil
}
