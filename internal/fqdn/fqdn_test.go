// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions of this file are based on code originally:
 *
 * Copyright since 2015 Showmax s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fqdn

import (
	"net"
	"os/exec"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// This package is hard to reasonably test in isolation, so take a shortcut and
// assume that no one will set their hostname to localhost.
func TestHostname(t *testing.T) {
	fqdnHost, err := Hostname()
	require.NoError(t, err)

	require.NotEqual(t, "localhost", fqdnHost)

	// Ensure that the hostname is not an IP address.
	require.Nil(t, net.ParseIP(fqdnHost))
}

func TestFromLookup(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		fqdn, err := fromLookup("ipv4.google.com")
		require.NoError(t, err)

		require.Equal(t, "ipv4.l.google.com.", fqdn)
	})

	t.Run("IPv6", func(t *testing.T) {
		fqdn, err := fromLookup("ipv6.google.com")
		require.NoError(t, err)

		require.Equal(t, "ipv6.l.google.com.", fqdn)
	})

	t.Run("NotFound", func(t *testing.T) {
		_, err := fromLookup("makwjefalurgaf8")
		require.ErrorIs(t, err, ErrFqdnNotFound)
	})
}

// In order to behave in expected way, we should verify that we are producing
// same output has hostname utility.
func TestMatchHostname(t *testing.T) {
	out, err := exec.Command(hostnameBin, hostnameArgs...).Output()
	if err != nil {
		t.Fatalf("Could not run hostname: %v", err)
	}
	outS := dns.CanonicalName(strings.TrimSpace(string(out)))

	fqdn, err := Hostname()
	if err != nil {
		t.Fatalf("Could not fqdn hostname: %v", err)
	}

	// Since hostnames (domains) are case-insensitive and mac's hostname
	// returns it with uppercased first letter causing test to fail
	//
	//         	Us  : "mac-1271.local"
	//         	Them: "Mac-1271.local"
	//
	// we should compare lower-cased versions.
	outS = strings.ToLower(outS)
	fqdn = strings.ToLower(fqdn)

	// Windows github machines are flaky, and running hostname on them
	// sometimes returns short name, sometimes fqdn. Not sure what is the
	// cause. Workaround is to ignore results from the system which do not
	// have `.' in them.
	if !strings.ContainsRune(outS, '.') {
		return
	}

	require.Equal(t, outS, fqdn, "Output from hostname does not match")
}
