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
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/noisysockets/resolver/internal/dnsconfig"
)

// SystemResolverConfig is the configuration for a system resolver.
type SystemResolverConfig struct {
	// Timeout is the maximum duration to wait for a query to complete
	// (including retries).
	Timeout *time.Duration
	// DialContext is used to establish a connection to a DNS server.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	// TLSClientConfig is the configuration for the TLS client used for DNS over TLS.
	TLSClientConfig *tls.Config
}

// System returns a Resolver that uses the system's default DNS configuration.
func System(conf *SystemResolverConfig) (Resolver, error) {
	if conf == nil {
		conf = &SystemResolverConfig{}
	}

	systemDNSConf, err := dnsconfig.Read("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("failed to read system DNS configuration: %w", err)
	}

	timeout := conf.Timeout
	if systemDNSConf.Timeout > 0 {
		timeout = &systemDNSConf.Timeout
	}

	protocol := ProtocolUDP
	if systemDNSConf.UseTCP {
		protocol = ProtocolTCP
	}

	var resolvers []Resolver
	for _, server := range systemDNSConf.Servers {
		addrPort, err := netip.ParseAddrPort(server)
		if err != nil {
			return nil, fmt.Errorf("failed to parse server address %q: %w", server, err)
		}

		resolvers = append(resolvers, DNS(&DNSResolverConfig{
			Protocol:        protocol,
			Server:          addrPort,
			Timeout:         timeout,
			DialContext:     conf.DialContext,
			TLSClientConfig: conf.TLSClientConfig,
		}))
	}

	var resolver Resolver
	if systemDNSConf.Rotate {
		resolver = RoundRobin(resolvers...)
	} else {
		resolver = Chain(resolvers...)
	}

	if len(systemDNSConf.Search) > 0 && !(len(systemDNSConf.Search) == 1 && systemDNSConf.Search[0] == ".") {
		resolver = Relative(resolver, &RelativeResolverConfig{
			Search: systemDNSConf.Search,
			NDots:  systemDNSConf.NDots,
		})
	}

	// TODO: the timeout is meant to include retries.
	if systemDNSConf.Attempts > 0 {
		resolver = Retry(resolver, &RetryResolverConfig{
			Attempts: systemDNSConf.Attempts,
		})
	}

	return resolver, nil
}
