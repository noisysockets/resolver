// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package resolver

import (
	"errors"
	"strings"

	"github.com/miekg/dns"
	"github.com/noisysockets/resolver/internal/fqdn"
)

// Domain returns the domain of the local machine.
func Domain() (string, error) {
	hn, err := fqdn.Hostname()
	if err != nil {
		return "", err
	}

	labels := dns.SplitDomainName(hn)
	if len(labels) < 1 {
		return "", errors.New("invalid hostname")
	}

	return dns.CanonicalName(strings.Join(labels[1:], ".")), nil
}
