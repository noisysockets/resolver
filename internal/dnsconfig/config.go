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
	"time"

	"github.com/noisysockets/resolver/internal/fqdn"
)

var (
	defaultNS       = []string{"127.0.0.1:53", "[::1]:53"}
	getFqdnHostname = fqdn.Hostname // variable for testing
)

// Config is the system DNS configuration.
type Config struct {
	Servers       []string      // server addresses (in host:port form) to use
	Search        []string      // rooted suffixes to append to local name
	NDots         int           // number of dots in name to trigger absolute lookup
	Timeout       time.Duration // wait before giving up on a query.
	Attempts      int           // lost packets before giving up on server
	Rotate        bool          // round robin among servers
	UnknownOpt    bool          // anything unknown was encountered
	Lookup        []string      // OpenBSD top-level database "lookup" order
	MTime         time.Time     // time of resolv.conf modification
	SingleRequest bool          // use sequential A and AAAA queries instead of parallel queries
	UseTCP        bool          // force usage of TCP for DNS resolutions
	TrustAD       bool          // add AD flag to queries
	NoReload      bool          // do not check for config file updates
}
