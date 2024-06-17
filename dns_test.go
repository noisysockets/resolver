// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package resolver_test

import (
	"context"
	"crypto/tls"
	"net/netip"
	"testing"

	"github.com/noisysockets/resolver"
	"github.com/noisysockets/util/ptr"
	"github.com/stretchr/testify/require"
)

func TestDNSResolver(t *testing.T) {
	expected := []netip.Addr{
		netip.MustParseAddr("2001:4860:4860::8888"),
		netip.MustParseAddr("2001:4860:4860::8844"),
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("8.8.4.4"),
	}

	t.Run("UDP", func(t *testing.T) {
		res := resolver.DNS(resolver.DNSResolverConfig{
			Server: netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), 0),
		})

		addrs, err := res.LookupNetIP(context.Background(), "ip", "dns.google")
		require.NoError(t, err)

		require.ElementsMatch(t, expected, addrs)
	})

	t.Run("TCP", func(t *testing.T) {
		res := resolver.DNS(resolver.DNSResolverConfig{
			Server:    netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), 0),
			Transport: ptr.To(resolver.DNSTransportTCP),
		})

		addrs, err := res.LookupNetIP(context.Background(), "ip", "dns.google")
		require.NoError(t, err)

		require.ElementsMatch(t, expected, addrs)
	})

	t.Run("TLS", func(t *testing.T) {
		res := resolver.DNS(resolver.DNSResolverConfig{
			Server:    netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), 0),
			Transport: ptr.To(resolver.DNSTransportTLS),
			TLSConfig: &tls.Config{
				ServerName: "dns.google",
			},
		})

		addrs, err := res.LookupNetIP(context.Background(), "ip", "dns.google")
		require.NoError(t, err)

		require.ElementsMatch(t, expected, addrs)
	})
}
