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

func TestDNS64Resolver(t *testing.T) {
	res := resolver.DNS64(resolver.Literal(), nil)

	t.Run("IPv4", func(t *testing.T) {
		addrs, err := res.LookupNetIP(context.Background(), "ip6", "10.0.0.1")
		require.NoError(t, err)

		require.Equal(t, []netip.Addr{netip.MustParseAddr("64:ff9b::a00:1")}, addrs)
	})

	t.Run("IPv6", func(t *testing.T) {
		addrs, err := res.LookupNetIP(context.Background(), "ip6", "2001:db8:85a3::8a2e:370:7334")
		require.NoError(t, err)

		require.Equal(t, []netip.Addr{netip.MustParseAddr("2001:db8:85a3::8a2e:370:7334")}, addrs)
	})
}
