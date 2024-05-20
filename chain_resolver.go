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
)

var (
	_ Resolver = (*chainResolver)(nil)
)

// chainResolver is a Resolver that chains multiple resolvers.
type chainResolver struct {
	resolvers []Resolver
}

// Chain returns a Resolver that chains the given resolvers. It tries each
// resolver in order until one of them returns a non-nil result.
func Chain(resolvers ...Resolver) *chainResolver {
	return &chainResolver{resolvers: resolvers}
}

// LookupHost looks up the given host using the resolvers. It returns a slice
// of that host's addresses.
func (r *chainResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	var firstErr error
	for _, resolver := range r.resolvers {
		addrs, err := resolver.LookupHost(ctx, host)
		if err == nil {
			return addrs, nil
		} else if firstErr == nil {
			firstErr = err
		}
	}

	if firstErr != nil {
		return nil, firstErr
	}

	return nil, &net.DNSError{
		Err:        ErrNoSuchHost.Error(),
		Name:       host,
		IsNotFound: true,
	}
}

// LookupNetIP looks up host using the resolvers. It returns a slice of that
// host's IP addresses of the type specified by network. The network must be
// one of "ip", "ip4" or "ip6".
func (r *chainResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	var firstErr error
	for _, resolver := range r.resolvers {
		addrs, err := resolver.LookupNetIP(ctx, network, host)
		if err == nil {
			return addrs, nil
		} else if firstErr == nil {
			firstErr = err
		}
	}

	if firstErr != nil {
		return nil, firstErr
	}

	return nil, &net.DNSError{
		Err:        ErrNoSuchHost.Error(),
		Name:       host,
		IsNotFound: true,
	}
}
