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
	"errors"
	"net/netip"
)

var _ Resolver = (*sequentialResolver)(nil)

// sequentialResolver is a resolver that tries each resolver in order until one succeeds.
type sequentialResolver struct {
	resolvers []Resolver
}

// Sequential returns a resolver that tries each resolver in order until one succeeds.
func Sequential(resolvers ...Resolver) *sequentialResolver {
	return &sequentialResolver{
		resolvers: resolvers,
	}
}

func (r *sequentialResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	var errs []error
	for _, resolver := range r.resolvers {
		addrs, err := resolver.LookupNetIP(ctx, network, host)
		if err == nil {
			return addrs, nil
		}
		errs = append(errs, err)
	}

	return nil, errors.Join(errs...)
}
