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
 * Copyright (c) 2012 The Go Authors. All rights reserved.
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

package resolver

import (
	"context"
	"net/netip"
	"time"
)

// Protocol is the protocol used for DNS resolution.
type Protocol string

const (
	// ProtocolUDP is the DNS over UDP as defined in RFC 1035.
	ProtocolUDP Protocol = "udp"
	// ProtocolTCP is the DNS over TCP as defined in RFC 1035.
	ProtocolTCP Protocol = "tcp"
	// ProtocolTLS is the DNS over TLS as defined in RFC 7858.
	ProtocolTLS Protocol = "tls"
)

// Resolver looks up names and numbers.
type Resolver interface {
	// LookupHost looks up the given host using the resolver. It returns a slice
	// of that host's addresses.
	LookupHost(ctx context.Context, host string) (addrs []string, err error)
	// LookupNetIP looks up host using the resolver. It returns a slice of that
	// host's IP addresses of the type specified by network. The network must be
	// one of "ip", "ip4" or "ip6".
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Default is the default resolver.
var Default Resolver = Chain(IP(), DNS(&DNSResolverConfig{
	// Use Google's public DNS servers (DNS over TLS).
	Protocol: ProtocolTLS,
	Servers: []netip.AddrPort{
		netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), 853),
		netip.AddrPortFrom(netip.MustParseAddr("8.8.4.4"), 853),
	},
	// Enable load balancing.
	Rotate: true,
	// Use a 5 second timeout for queries.
	Timeout: 5 * time.Second,
}))
