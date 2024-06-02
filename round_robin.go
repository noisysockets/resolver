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
	"net/netip"

	"github.com/noisysockets/resolver/internal/util"
)

var _ Resolver = (*roundRobinResolver)(nil)

// roundRobinResolver is a Resolver that load balances between multiple resolvers
// using a round-robin strategy.
type roundRobinResolver struct {
	resolvers []Resolver
}

// RoundRobin returns a Resolver that load balances between multiple resolvers
// using a round-robin strategy.
func RoundRobin(resolvers ...Resolver) *roundRobinResolver {
	return &roundRobinResolver{
		resolvers: resolvers,
	}
}

func (r *roundRobinResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	rotatedResolvers := make([]Resolver, len(r.resolvers))
	copy(rotatedResolvers, r.resolvers)
	rotatedResolvers = util.Shuffle(rotatedResolvers)

	return Sequential(rotatedResolvers...).LookupNetIP(ctx, network, host)
}
