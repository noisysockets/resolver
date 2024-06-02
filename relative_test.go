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
	"net"
	"net/netip"
	"testing"

	"github.com/noisysockets/resolver"
	"github.com/noisysockets/resolver/internal/testutil"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestRelativeResolver(t *testing.T) {
	inner := new(testutil.MockResolver)
	inner.On("LookupNetIP", mock.Anything, "ip", "www.example.com.").Return([]netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil)
	inner.On("LookupNetIP", mock.Anything, "ip", "www.foobar.com.").Return([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil)
	inner.On("LookupNetIP", mock.Anything, "ip", mock.Anything).Return([]netip.Addr{}, &net.DNSError{
		Err:        resolver.ErrNoSuchHost.Error(),
		IsNotFound: true,
	})

	res := resolver.Relative(inner, &resolver.RelativeResolverConfig{
		Search: []string{"example.com."},
	})

	t.Run("Relative", func(t *testing.T) {
		addrs, err := res.LookupNetIP(context.Background(), "ip", "www")
		require.NoError(t, err)

		require.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, addrs)
	})

	t.Run("Absolute", func(t *testing.T) {
		addrs, err := res.LookupNetIP(context.Background(), "ip", "www.foobar.com")
		require.NoError(t, err)

		require.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.2")}, addrs)
	})

	t.Run("Absolute (No Such Domain)", func(t *testing.T) {
		_, err := res.LookupNetIP(context.Background(), "ip", "www.")

		var dnsErr *net.DNSError
		require.ErrorAs(t, err, &dnsErr)
		require.Equal(t, resolver.ErrNoSuchHost.Error(), dnsErr.Err)
	})
}
