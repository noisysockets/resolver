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
	"github.com/noisysockets/resolver/internal/testutil"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestPreferredAddressResolver(t *testing.T) {
	testutil.EnsureIPv6(t)

	inner := new(testutil.MockResolver)
	inner.On("LookupNetIP", mock.Anything, "ip", "www.example.com.").Return([]netip.Addr{
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("2001:db8::10"),
	}, nil)

	res := resolver.PreferredAddress(inner, nil)

	addrs, err := res.LookupNetIP(context.Background(), "ip", "www.example.com.")
	require.NoError(t, err)

	expected := []netip.Addr{
		netip.MustParseAddr("2001:db8::10"),
		netip.MustParseAddr("10.0.0.1"),
	}

	require.Equal(t, expected, addrs)
}
