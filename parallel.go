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
	"sync"
)

var _ Resolver = (*parallelResolver)(nil)

// parallelResolver is a resolver that tries each resolver in parallel until
// one succeeds.
type parallelResolver struct {
	resolvers []Resolver
}

// Parallel returns a resolver that tries each resolver in parallel until one
// succeeds.
func Parallel(resolvers []Resolver) *parallelResolver {
	return &parallelResolver{
		resolvers: resolvers,
	}
}

func (r *parallelResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	results := make(chan []netip.Addr)

	var errsMu sync.Mutex
	var errs []error

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(len(r.resolvers))

	go func() {
		wg.Wait()

		close(results)
	}()

	for _, resolver := range r.resolvers {
		go func(resolver Resolver) {
			defer wg.Done()

			addrs, err := resolver.LookupNetIP(ctx, network, host)
			if err == nil {
				results <- addrs
			}

			errsMu.Lock()
			errs = append(errs, err)
			errsMu.Unlock()
		}(resolver)
	}

	select {
	case addrs, ok := <-results:
		if !ok {
			return nil, errors.Join(errs...)
		}

		return addrs, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
