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

func TestLiteralResolver(t *testing.T) {
	res := resolver.Literal()

	t.Run("IP", func(t *testing.T) {
		addrs, err := res.LookupNetIP(context.Background(), "ip", "10.0.0.1")
		require.NoError(t, err)

		require.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, addrs)
	})

	t.Run("IPv4", func(t *testing.T) {
		addrs, err := res.LookupNetIP(context.Background(), "ip4", "10.0.0.1")
		require.NoError(t, err)

		require.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, addrs)
	})

	t.Run("IPv6", func(t *testing.T) {
		addrs, err := res.LookupNetIP(context.Background(), "ip6", "2001:db8::1")
		require.NoError(t, err)

		require.Equal(t, []netip.Addr{netip.MustParseAddr("2001:db8::1")}, addrs)
	})

	t.Run("Domain Name", func(t *testing.T) {
		_, err := res.LookupNetIP(context.Background(), "ip", "example.com")
		require.Error(t, err)
	})

	t.Run("Localhost", func(t *testing.T) {
		addrs, err := res.LookupNetIP(context.Background(), "ip", "localhost")
		require.NoError(t, err)

		require.Equal(t, []netip.Addr{netip.IPv6Loopback(), netip.MustParseAddr("127.0.0.1")}, addrs)
	})
}
