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
	"testing"

	"github.com/noisysockets/resolver"
	"github.com/noisysockets/resolver/testutil"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestRetryResolver(t *testing.T) {
	res1 := new(testutil.MockResolver)
	res1.On("LookupHost", mock.Anything, "notfound.com").Return([]string{}, &net.DNSError{
		Err:        resolver.ErrNoSuchHost.Error(),
		IsNotFound: true,
	})
	res1.On("LookupHost", mock.Anything, "example.com").Return([]string{}, &net.DNSError{
		Err:         resolver.ErrServerMisbehaving.Error(),
		IsTemporary: true,
	})

	res := resolver.Retry(res1, &resolver.RetryResolverConfig{Attempts: 3})

	t.Run("LookupHost", func(t *testing.T) {
		t.Run("Retryable", func(t *testing.T) {
			_, err := res.LookupHost(context.Background(), "example.com")
			require.Error(t, err)

			dnsErr, ok := err.(*net.DNSError)
			require.True(t, ok)

			require.Equal(t, resolver.ErrServerMisbehaving.Error(), dnsErr.Err)

			res1.AssertNumberOfCalls(t, "LookupHost", 3)

			// Reset the mock
			res1.Calls = nil
		})

		t.Run("Not Retryable", func(t *testing.T) {
			_, err := res.LookupHost(context.Background(), "notfound.com")
			require.Error(t, err)

			dnsErr, ok := err.(*net.DNSError)
			require.True(t, ok)

			require.Equal(t, resolver.ErrNoSuchHost.Error(), dnsErr.Err)

			res1.AssertNumberOfCalls(t, "LookupHost", 1)

			// Reset the mocsk
			res1.Calls = nil
		})
	})
}
