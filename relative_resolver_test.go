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
	"github.com/noisysockets/resolver/testutil"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestRelativeResolver(t *testing.T) {
	addr := netip.MustParseAddr("10.0.0.1")

	inner := new(testutil.MockResolver)
	inner.On("LookupNetIP", mock.Anything, "ip", "www.example.com.").Return([]netip.Addr{addr}, nil)

	res := resolver.Relative(inner, &resolver.RelativeResolverConfig{
		Search: []string{"example.com."},
		NDots:  1,
	})

	t.Run("LookupHost", func(t *testing.T) {
		addrs, err := res.LookupHost(context.Background(), "www")
		require.NoError(t, err)

		require.Equal(t, []string{"10.0.0.1"}, addrs)
	})
}
