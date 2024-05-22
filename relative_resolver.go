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
	"strings"

	"github.com/miekg/dns"
	"github.com/noisysockets/resolver/util"
)

var (
	_ Resolver = (*relativeResolver)(nil)
)

// RelativeResolverConfig is the configuration for a relative domain resolver.
type RelativeResolverConfig struct {
	// Search is a list of rooted suffixes to append to the relative name.
	Search []string
	// NDots is the number of dots in a name to trigger an absolute lookup.
	NDots int
}

// relativeResolver is a Resolver that resolves relative domain names.
type relativeResolver struct {
	inner  Resolver
	search []string
	ndots  int
}

// Relative creates a new relative name resolver.
func Relative(inner Resolver, conf *RelativeResolverConfig) *relativeResolver {
	if conf == nil {
		conf = &RelativeResolverConfig{
			Search: []string{"."},
			NDots:  1,
		}
	}

	return &relativeResolver{
		inner:  inner,
		search: conf.Search,
		ndots:  conf.NDots,
	}
}

func (r *relativeResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	addrs, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	return util.Strings(addrs), nil
}

func (r *relativeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	var names []string
	if ndots := strings.Count(host, "."); ndots < r.ndots {
		// If the name has fewer dots than the threshold, append the search
		// domains to the name.
		for _, domain := range r.search {
			name := util.Join(host, domain)
			if _, ok := dns.IsDomainName(name); ok {
				names = append(names, name)
			}
		}
	} else {
		names = []string{dns.Fqdn(host)}
	}

	var firstErr error
	for _, name := range names {
		addrs, err := r.inner.LookupNetIP(ctx, network, name)
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
