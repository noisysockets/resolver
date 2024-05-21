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
	"os"
	"testing"

	"github.com/noisysockets/resolver"
	"github.com/stretchr/testify/require"
)

func TestFileResolver(t *testing.T) {
	hostsfileReader, err := os.Open("testdata/hosts")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, hostsfileReader.Close())
	})

	res, err := resolver.File(hostsfileReader, nil)
	require.NoError(t, err)

	t.Run("LookupHost", func(t *testing.T) {
		addrs, err := res.LookupHost(context.Background(), "api.testserver.local")
		require.NoError(t, err)

		require.Equal(t, []string{"192.168.1.11", "2001:db8::2"}, addrs)
	})
}
