// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package util

import (
	"strings"

	"github.com/miekg/dns"
)

// Join joins a host and a domain into a single canonical name.
func Join(host, domain string) string {
	return dns.CanonicalName(strings.Join(append(dns.SplitDomainName(host),
		dns.SplitDomainName(domain)...), "."))
}
