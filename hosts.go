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
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"

	"github.com/miekg/dns"
	"github.com/noisysockets/netutil/addresses"
	"github.com/noisysockets/netutil/addrselect"
	"github.com/noisysockets/netutil/hostsfile"
	"github.com/noisysockets/resolver/internal/util"
)

var _ Resolver = (*hostsResolver)(nil)

type HostsResolverConfig struct {
	// HostsFileReader is an optional reader that will be used as the source of the hosts file.
	// If not provided, the OS's default hosts file will be used.
	HostsFileReader io.Reader
	// DialContext is an optional dialer used for ordering the returned addresses.
	DialContext DialContextFunc
}

type hostsResolver struct {
	addrsByName map[string][]netip.Addr
	dialContext DialContextFunc
}

func Hosts(conf *HostsResolverConfig) (*hostsResolver, error) {
	conf, err := util.ConfigWithDefaults(conf, &HostsResolverConfig{
		DialContext: (&net.Dialer{}).DialContext,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to apply defaults to hosts resolver config: %w", err)
	}

	// Don't incur the cost of opening the hosts file if a reader is already provided.
	if conf.HostsFileReader == nil {
		f, err := os.Open(hostsfile.Location)
		if err != nil {
			return nil, fmt.Errorf("failed to open hosts file: %w", err)
		}
		defer f.Close()

		conf.HostsFileReader = f
	}

	h, err := hostsfile.Decode(conf.HostsFileReader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse hosts file: %w", err)
	}

	addrsByName := make(map[string][]netip.Addr)
	for _, record := range h.Records() {
		for name := range record.Hostnames {
			name = dns.Fqdn(name)

			addr, err := netip.ParseAddr(record.IpAddress.String())
			if err != nil {
				return nil, fmt.Errorf("failed to parse IP address: %w", err)
			}

			addrsByName[name] = append(addrsByName[name], addr)
		}
	}

	return &hostsResolver{
		addrsByName: addrsByName,
		dialContext: conf.DialContext,
	}, nil
}

func (r *hostsResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	dnsErr := &net.DNSError{
		Name: host,
	}

	addrs, ok := r.addrsByName[dns.Fqdn(host)]
	if !ok {
		return nil, extendDNSError(dnsErr, net.DNSError{
			Err:        ErrNoSuchHost.Error(),
			IsNotFound: true,
		})
	}

	if network != "ip" && network != "ip4" && network != "ip6" {
		return nil, extendDNSError(dnsErr, net.DNSError{
			Err: ErrUnsupportedNetwork.Error(),
		})
	}

	addrs = addresses.FilterByNetwork(addrs, network)

	if network != "ip4" && len(addrs) > 0 {
		dial := func(network, address string) (net.Conn, error) {
			return r.dialContext(ctx, network, address)
		}

		addrselect.SortByRFC6724(dial, addrs)
	}

	return addrs, nil
}
