//go:build windows

// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions of this file are based on code originally from the Go project,
 *
 * Copyright (c) 2024 The Go Authors. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following disclaimer
 *     in the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Google Inc. nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package dnsconfig

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/windows"

	"github.com/noisysockets/resolver/internal/winipcfg"
)

// Read reads the system DNS config from the Windows registry.
func Read(ignoredFilename string) (*Config, error) {
	conf := &Config{
		NDots:    1,
		Timeout:  5 * time.Second,
		Attempts: 2,
	}

	// Get the IPv4 interface addresses.
	aasV4, err := winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagIncludeAllInterfaces)
	if err != nil {
		return nil, fmt.Errorf("failed to get adapter addresses: %w", err)
	}

	// Get IPv6 interface addresses as well.
	aasV6, err := winipcfg.GetAdaptersAddresses(windows.AF_INET6, winipcfg.GAAFlagIncludeAllInterfaces)
	if err != nil {
		return nil, fmt.Errorf("failed to get adapter addresses: %w", err)
	}

	for _, aa := range append(aasV4, aasV6...) {
		// Only take interfaces whose OperStatus is IfOperStatusUp(0x01) into DNS configs.
		if aa.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}

		// Only take interfaces which have at least one gateway.
		if aa.FirstGatewayAddress == nil {
			continue
		}

		dnsAddrs, err := aa.LUID.DNS()
		if err != nil {
			continue
		}

		for _, addr := range dnsAddrs {
			addr := addr.Unmap()
			if addr.Is6() && addr.AsSlice()[0] == 0xfe && addr.AsSlice()[1] == 0xc0 {
				// fec0/10 IPv6 addresses are site local anycast DNS
				// addresses Microsoft sets by default if no other
				// IPv6 DNS address is set. Site local anycast is
				// deprecated since 2004, see
				// https://datatracker.ietf.org/doc/html/rfc3879
				continue
			}

			conf.Servers = append(conf.Servers, net.JoinHostPort(addr.String(), "53"))
		}
	}

	if len(conf.Servers) == 0 {
		conf.Servers = defaultNS
	}

	return conf, nil
}
