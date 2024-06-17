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
	"strings"

	"github.com/miekg/dns"
	"github.com/noisysockets/resolver/util"
	"github.com/noisysockets/util/defaults"
	"github.com/noisysockets/util/ptr"
)

var _ Resolver = (*relativeResolver)(nil)

// RelativeResolverConfig is the configuration for a relative domain resolver.
type RelativeResolverConfig struct {
	// Search is a list of rooted suffixes to append to the relative name.
	Search []string
	// NDots is the number of dots in a name to trigger an absolute lookup.
	NDots *int
}

type relativeResolver struct {
	resolver Resolver
	search   []string
	nDots    int
}

// Relative returns a resolver that resolves relative hostnames.
func Relative(resolver Resolver, conf *RelativeResolverConfig) *relativeResolver {
	conf, err := defaults.WithDefaults(conf, &RelativeResolverConfig{
		Search: []string{"."},
		NDots:  ptr.To(1),
	})
	if err != nil {
		// Should never happen.
		panic(err)
	}

	return &relativeResolver{
		resolver: resolver,
		search:   conf.Search,
		nDots:    *conf.NDots,
	}
}

func (r *relativeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	names := []string{dns.Fqdn(host)}

	if nDots := strings.Count(host, "."); !strings.HasSuffix(host, ".") && nDots < r.nDots {
		// If the name has fewer dots than the threshold, append the search
		// domains to the name.
		names = nil
		for _, domain := range r.search {
			name := util.Join(host, domain)
			if _, ok := dns.IsDomainName(name); ok {
				names = append(names, name)
			}
		}
	}

	var errs []error
	for _, name := range names {
		addrs, err := r.resolver.LookupNetIP(ctx, network, name)
		if err == nil {
			return addrs, nil
		}
		errs = append(errs, err)
	}

	return nil, errors.Join(errs...)
}
