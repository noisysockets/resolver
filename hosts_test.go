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
	"os"
	"testing"

	"github.com/noisysockets/resolver"
	"github.com/stretchr/testify/require"
)

func TestHostsResolver(t *testing.T) {
	f, err := os.Open("testdata/hosts")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, f.Close())
	})

	res, err := resolver.Hosts(&resolver.HostsResolverConfig{
		HostsFileReader: f,
	})
	require.NoError(t, err)

	addrs, err := res.LookupNetIP(context.Background(), "ip", "api.testserver.local")
	require.NoError(t, err)

	require.ElementsMatch(t, []netip.Addr{netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("192.168.1.11")}, addrs)

	addrs, err = res.LookupNetIP(context.Background(), "ip4", "api.testserver.local")
	require.NoError(t, err)

	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.1.11")}, addrs)

	// Add an ephemeral host
	res.AddHost("api2.testserver.local", netip.MustParseAddr("192.168.2.11"))

	addrs, err = res.LookupNetIP(context.Background(), "ip", "api2.testserver.local")
	require.NoError(t, err)

	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.2.11")}, addrs)

	// Remove the ephemeral host
	res.RemoveHost("api2.testserver.local")

	_, err = res.LookupNetIP(context.Background(), "ip", "api2.testserver.local")
	require.Error(t, err)
}
