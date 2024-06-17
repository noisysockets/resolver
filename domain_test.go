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
	"testing"

	"github.com/noisysockets/resolver"
	"github.com/stretchr/testify/require"
)

func TestDomain(t *testing.T) {
	domain, err := resolver.Domain()
	require.NoError(t, err)

	require.NotEmpty(t, domain)
	require.NotEqual(t, ".", domain)
}
