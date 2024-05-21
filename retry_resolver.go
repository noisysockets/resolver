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
)

var (
	_ Resolver = (*retryResolver)(nil)
)

type retryResolver struct {
	inner    Resolver
	attempts int
}

// RetryResolverConfig is the configuration for a retry resolver.
type RetryResolverConfig struct {
	// Attempts is the number of attempts to make before giving up.
	// Setting this to 0 will cause the resolver to retry forever.
	Attempts int
}

// Retry creates a new resolver that retries the inner resolver a configurable
// number of times (for temporary errors).
func Retry(inner Resolver, conf *RetryResolverConfig) Resolver {
	return &retryResolver{inner: inner, attempts: conf.Attempts}
}

func (r *retryResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return retry.DoWithData(func() ([]string, error) {
		return r.inner.LookupHost(ctx, host)
	},
		retry.Context(ctx),
		retry.Attempts(uint(r.attempts)),
		retry.RetryIf(isTemporary),
		retry.LastErrorOnly(true),
	)
}

func (r *retryResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return retry.DoWithData(func() ([]netip.Addr, error) {
		return r.inner.LookupNetIP(ctx, network, host)
	},
		retry.Context(ctx),
		retry.Attempts(uint(r.attempts)),
		retry.RetryIf(isTemporary),
		retry.LastErrorOnly(true),
	)
}
