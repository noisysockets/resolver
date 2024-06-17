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
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/noisysockets/resolver/internal/dnsconfig"
	"github.com/noisysockets/util/defaults"
	"github.com/noisysockets/util/ptr"
)

// SystemResolverConfig is the configuration for a system resolver.
type SystemResolverConfig struct {
	// HostsFilePath is the optional path to the hosts file.
	// By default, the system's hosts file is used.
	HostsFilePath string
	// DialContext is used to establish a connection to a DNS server.
	DialContext DialContextFunc
}

// System returns a Resolver that uses the system's default DNS configuration.
func System(conf *SystemResolverConfig) (Resolver, error) {
	conf, err := defaults.WithDefaults(conf, &SystemResolverConfig{
		DialContext: (&net.Dialer{}).DialContext,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to apply defaults to system resolver config: %w", err)
	}

	systemDNSConf, err := dnsconfig.Read(dnsconfig.Location)
	if err != nil {
		return nil, fmt.Errorf("failed to read system DNS configuration: %w", err)
	}

	transport := DNSTransportUDP
	if systemDNSConf.UseTCP {
		transport = DNSTransportTCP
	}

	var resolvers []Resolver
	for _, server := range systemDNSConf.Servers {
		addrPort, err := netip.ParseAddrPort(server)
		if err != nil {
			return nil, fmt.Errorf("failed to parse server address %q: %w", server, err)
		}

		var timeout *time.Duration
		if systemDNSConf.Timeout > 0 {
			timeout = &systemDNSConf.Timeout
		}

		resolvers = append(resolvers, DNS(DNSResolverConfig{
			Server:        addrPort,
			Transport:     &transport,
			Timeout:       timeout,
			DialContext:   conf.DialContext,
			SingleRequest: &systemDNSConf.SingleRequest,
		}))
	}

	var resolver Resolver
	if systemDNSConf.Rotate {
		resolver = RoundRobin(resolvers...)
	} else {
		resolver = Sequential(resolvers...)
	}

	// TODO: I'm pretty sure that glibc counts attempts differently, eg. not on a
	// per nameserver basis.
	var attempts *int
	if systemDNSConf.Attempts > 0 {
		attempts = &systemDNSConf.Attempts
	}

	resolver = Retry(resolver, &RetryResolverConfig{
		Attempts: attempts,
	})

	if len(systemDNSConf.Search) > 0 {
		var nDots *int
		if systemDNSConf.NDots >= 0 {
			nDots = ptr.To(systemDNSConf.NDots)
		}

		resolver = Relative(resolver, &RelativeResolverConfig{
			Search: systemDNSConf.Search,
			NDots:  nDots,
		})
	}

	var hostsFileReader io.Reader
	if conf.HostsFilePath != "" {
		f, err := os.Open(conf.HostsFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to open hosts file %q: %w", conf.HostsFilePath, err)
		}
		defer f.Close()

		hostsFileReader = f
	}

	hostsResolver, err := Hosts(&HostsResolverConfig{
		HostsFileReader: hostsFileReader,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create hosts file resolver: %w", err)
	}

	return Sequential(Literal(), hostsResolver, resolver), nil
}
