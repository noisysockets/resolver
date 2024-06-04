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
	"context"
	"net"
	"net/netip"

	"github.com/noisysockets/resolver/internal/addrselect"
	"github.com/noisysockets/resolver/internal/util"
)

var _ Resolver = (*preferredAddressResolver)(nil)

type PreferredAddressResolverConfig struct {
	// DialContext is an optional dialer used for ordering the returned addresses.
	DialContext DialContextFunc
}

// preferredAddressResolver is a resolver that orders the returned addresses according to RFC 6724.
type preferredAddressResolver struct {
	resolver    Resolver
	dialContext DialContextFunc
}

// PreferredAddress returns a resolver that orders the returned addresses according to RFC 6724.
func PreferredAddress(resolver Resolver, conf *PreferredAddressResolverConfig) *preferredAddressResolver {
	conf, err := util.ConfigWithDefaults(conf, &PreferredAddressResolverConfig{
		DialContext: (&net.Dialer{}).DialContext,
	})
	if err != nil {
		// Should never happen.
		panic(err)
	}

	return &preferredAddressResolver{
		resolver:    resolver,
		dialContext: conf.DialContext,
	}
}

func (r *preferredAddressResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	addrs, err := r.resolver.LookupNetIP(ctx, network, host)
	if err != nil {
		return nil, err
	}

	if network != "ip4" && len(addrs) > 0 {
		dial := func(network, address string) (net.Conn, error) {
			return r.dialContext(ctx, network, address)
		}

		addrselect.SortByRFC6724(dial, addrs)
	}

	return addrs, nil
}
