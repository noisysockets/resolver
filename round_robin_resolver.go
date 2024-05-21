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

	"github.com/noisysockets/resolver/util"
)

var (
	_ Resolver = (*roundRobinResolver)(nil)
)

// roundRobinResolver is a Resolver that load balances between multiple resolvers by
// chaining them in a random order.
type roundRobinResolver struct {
	resolvers []Resolver
}

// RoundRobin returns a Resolver that load balances between multiple resolvers by
// chaining them in a random order.
func RoundRobin(resolvers ...Resolver) *roundRobinResolver {
	return &roundRobinResolver{resolvers: resolvers}
}

func (r *roundRobinResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	resolvers := make([]Resolver, len(r.resolvers))
	copy(resolvers, r.resolvers)
	resolvers = util.Shuffle(resolvers)

	var firstErr error
	for _, resolver := range resolvers {
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

func (r *roundRobinResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	resolvers := make([]Resolver, len(r.resolvers))
	copy(resolvers, r.resolvers)
	resolvers = util.Shuffle(resolvers)

	var firstErr error
	for _, resolver := range resolvers {
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
