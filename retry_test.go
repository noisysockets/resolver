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

func TestRetryResolver(t *testing.T) {
	inner := new(testutil.MockResolver)
	inner.On("LookupNetIP", mock.Anything, mock.Anything, "notfound.com").Return([]netip.Addr{}, &net.DNSError{
		Err:        resolver.ErrNoSuchHost.Error(),
		IsNotFound: true,
	})
	inner.On("LookupNetIP", mock.Anything, mock.Anything, "example.com").Return([]netip.Addr{}, &net.DNSError{
		Err:         resolver.ErrServerMisbehaving.Error(),
		IsTemporary: true,
	})

	res := resolver.Retry(inner, nil)

	t.Run("Retryable", func(t *testing.T) {
		_, err := res.LookupNetIP(context.Background(), "ip", "example.com")
		require.Error(t, err)

		dnsErr, ok := err.(*net.DNSError)
		require.True(t, ok)

		require.Equal(t, resolver.ErrServerMisbehaving.Error(), dnsErr.Err)

		inner.AssertNumberOfCalls(t, "LookupNetIP", 2)

		// Reset the mock
		inner.Calls = nil
	})

	t.Run("Not Retryable", func(t *testing.T) {
		_, err := res.LookupNetIP(context.Background(), "ip", "notfound.com")
		require.Error(t, err)

		dnsErr, ok := err.(*net.DNSError)
		require.True(t, ok)

		require.Equal(t, resolver.ErrNoSuchHost.Error(), dnsErr.Err)

		inner.AssertNumberOfCalls(t, "LookupNetIP", 1)

		// Reset the mocsk
		inner.Calls = nil
	})
}
