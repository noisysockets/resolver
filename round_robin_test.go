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
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/noisysockets/resolver"
	"github.com/noisysockets/resolver/internal/testutil"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestRoundRobinResolver(t *testing.T) {
	res1 := new(testutil.MockResolver)
	res1.On("LookupNetIP", mock.Anything, mock.Anything, mock.Anything).Return([]netip.Addr{}, &net.DNSError{
		Err:        resolver.ErrNoSuchHost.Error(),
		IsNotFound: true,
	})

	res2 := new(testutil.MockResolver)
	res2.On("LookupNetIP", mock.Anything, "ip", "example.com").Return([]netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil)
	res2.On("LookupNetIP", mock.Anything, mock.Anything, mock.Anything).Return([]netip.Addr{}, &net.DNSError{
		Err:        resolver.ErrNoSuchHost.Error(),
		IsNotFound: true,
	})

	res := resolver.RoundRobin([]resolver.Resolver{res1, res2})

	t.Run("Success", func(t *testing.T) {
		addrs, err := res.LookupNetIP(context.Background(), "ip", "example.com")
		require.NoError(t, err)

		require.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, addrs)
	})

	t.Run("Not Found", func(t *testing.T) {
		_, err := res.LookupNetIP(context.Background(), "ip", "notfound.com")

		var dnsErr *net.DNSError
		require.True(t, errors.As(err, &dnsErr))

		require.Equal(t, resolver.ErrNoSuchHost.Error(), dnsErr.Err)
	})

	t.Run("Balances Load", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			_, err := res.LookupNetIP(context.Background(), "ip", "example.com")
			require.NoError(t, err)
		}

		// Make sure both resolvers were called.
		require.GreaterOrEqual(t, len(res1.Calls), 10)
		require.GreaterOrEqual(t, len(res2.Calls), 10)
	})
}
