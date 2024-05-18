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

func TestChainResolver(t *testing.T) {
	res1 := new(testutil.MockResolver)
	res1.On("LookupHost", mock.Anything, mock.Anything).Return([]string{}, &net.DNSError{
		Err:        resolver.ErrNoSuchHost.Error(),
		IsNotFound: true,
	})

	res2 := new(testutil.MockResolver)
	res2.On("LookupHost", mock.Anything, "example.com").Return([]string{"10.0.0.1"}, nil)
	res2.On("LookupHost", mock.Anything, mock.Anything).Return([]string{}, &net.DNSError{
		Err:        resolver.ErrNoSuchHost.Error(),
		IsNotFound: true,
	})

	res := resolver.Chain(res1, res2)

	t.Run("LookupHost", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			addrs, err := res.LookupHost(context.Background(), "example.com")
			require.NoError(t, err)

			require.Equal(t, []string{"10.0.0.1"}, addrs)
		})

		t.Run("Not Found", func(t *testing.T) {
			_, err := res.LookupHost(context.Background(), "notfound.com")

			dnsErr, ok := err.(*net.DNSError)
			require.True(t, ok)

			require.Equal(t, resolver.ErrNoSuchHost.Error(), dnsErr.Err)
		})
	})
}
