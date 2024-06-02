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

	"github.com/avast/retry-go/v4"
	"github.com/noisysockets/resolver/internal/util"
)

var _ Resolver = (*retryResolver)(nil)

// RetryResolverConfig is the configuration for a retry resolver.
type RetryResolverConfig struct {
	// Attempts is the number of attempts to make before giving up.
	// Setting this to 0 will cause the resolver to retry indefinitely.
	Attempts *int
}

// retryResolver is a resolver that retries a resolver a number of times.
type retryResolver struct {
	resolver Resolver
	attempts int
}

// Retry returns a resolver that retries a resolver a number of times.
func Retry(resolver Resolver, conf *RetryResolverConfig) *retryResolver {
	conf, err := util.ConfigWithDefaults(conf, &RetryResolverConfig{
		Attempts: util.PointerTo(2), // glibc defaults to 2 attempts.
	})
	if err != nil {
		// Should never happen.
		panic(err)
	}

	return &retryResolver{
		resolver: resolver,
		attempts: *conf.Attempts,
	}
}

func (r *retryResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return retry.DoWithData(func() ([]netip.Addr, error) {
		return r.resolver.LookupNetIP(ctx, network, host)
	},
		retry.Context(ctx),
		retry.Attempts(uint(r.attempts)),
		retry.RetryIf(isTemporary),
		retry.LastErrorOnly(true),
	)
}
