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
	"net/netip"
)

// FilterAddresses filters out addresses that are not of the requested family.
func FilterAddresses(allAddrs []netip.Addr, network string) ([]netip.Addr, error) {
	var addrs []netip.Addr
	for _, addr := range allAddrs {
		switch network {
		case "ip":
			addrs = append(addrs, addr)
		case "ip4":
			if addr.Unmap().Is4() {
				addrs = append(addrs, addr.Unmap())
			}
		case "ip6":
			if addr.Is6() {
				addrs = append(addrs, addr)
			}
		}
	}
	return addrs, nil
}
