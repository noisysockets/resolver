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
	"net/netip"
	"testing"

	"github.com/noisysockets/resolver"
	"github.com/stretchr/testify/require"
)

func TestSystemResolver(t *testing.T) {
	res, err := resolver.System(&resolver.SystemResolverConfig{
		HostsFilePath: "testdata/hosts",
	})
	require.NoError(t, err)

	t.Run("Literal", func(t *testing.T) {
		addrs, err := res.LookupNetIP(context.Background(), "ip", "8.8.8.8")
		require.NoError(t, err)

		require.Len(t, addrs, 1)
		require.Equal(t, netip.MustParseAddr("8.8.8.8"), addrs[0])

		addrs, err = res.LookupNetIP(context.Background(), "ip", "2001:4860:4860::8888")
		require.NoError(t, err)

		require.Len(t, addrs, 1)
		require.Equal(t, netip.MustParseAddr("2001:4860:4860::8888"), addrs[0])
	})

	t.Run("Host", func(t *testing.T) {
		addrs, err := res.LookupNetIP(context.Background(), "ip", "dev.mysite.com")
		require.NoError(t, err)

		expected := []netip.Addr{
			netip.MustParseAddr("10.0.0.10"),
			netip.MustParseAddr("2001:db8::10"),
		}

		require.ElementsMatch(t, expected, addrs)
	})

	t.Run("Domain", func(t *testing.T) {
		addrs, err := res.LookupNetIP(context.Background(), "ip", "dns.google")
		require.NoError(t, err)

		expected := []netip.Addr{
			netip.MustParseAddr("2001:4860:4860::8888"),
			netip.MustParseAddr("2001:4860:4860::8844"),
			netip.MustParseAddr("8.8.8.8"),
			netip.MustParseAddr("8.8.4.4"),
		}

		require.ElementsMatch(t, expected, addrs)
	})
}
