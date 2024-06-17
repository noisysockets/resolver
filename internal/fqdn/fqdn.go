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
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/noisysockets/resolver/internal/hostsfile"
)

// ErrFqdnNotFound is returned when fully qualified hostname cannot be found.
var ErrFqdnNotFound = errors.New("fqdn not found")

// Try to get fully qualified hostname for current machine.
//
// It tries to mimic how `hostname -f` works, so except for few edge cases you
// should get the same result from both. One thing that needs to be mentioned is
// that it does not guarantee that you get back fqdn. There is no way to do that
// and `hostname -f` can also return non-fqdn hostname if your /etc/hosts is
// malformed.
//
// It checks few sources in this order:
//
//  1. hosts file
//     It parses hosts file if present and readable and returns first canonical
//     hostname that also references your hostname. See hosts(5) for more
//     details.
//  2. dns lookup
//     If lookup in hosts file fails, it tries to ask dns.
func Hostname() (string, error) {
	host, err := os.Hostname()
	if err != nil {
		return "", err
	}

	fqdn, err := fromHosts(host)
	if err == nil {
		return fqdn, nil
	}

	fqdn, err = fromLookup(host)
	if err == nil {
		return fqdn, nil
	}

	return "", ErrFqdnNotFound
}

// Reads hosts(5) file and tries to get canonical name for host.
func fromHosts(host string) (string, error) {
	f, err := os.Open(hostsfile.Location)
	if err != nil {
		return "", fmt.Errorf("failed to open hosts file: %w", err)
	}
	defer f.Close()

	h, err := hostsfile.Decode(f)
	if err != nil {
		return "", fmt.Errorf("failed to parse hosts file: %w", err)
	}

	for _, record := range h.Records() {
		if record.Matches(host) {
			// The first hostname should always be canonical.
			return record.Hostnames[0], nil
		}
	}

	return "", ErrFqdnNotFound
}

func fromLookup(host string) (string, error) {
	fqdn, err := net.LookupCNAME(host)
	if err == nil && len(fqdn) != 0 {
		return fqdn, nil
	}

	addrs, err := net.LookupIP(host)
	if err != nil {
		return "", ErrFqdnNotFound
	}

	for _, addr := range addrs {
		hosts, err := net.LookupAddr(addr.String())
		// On windows it can return err == nil but empty list of hosts.
		if err != nil || len(hosts) == 0 {
			continue
		}

		// First one should be the canonical hostname.
		return hosts[0], nil
	}

	return "", ErrFqdnNotFound
}
