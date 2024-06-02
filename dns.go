// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions of this file are based on code originally from the Go project,
 *
 * Copyright (c) 2012 The Go Authors. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following disclaimer
 *     in the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Google Inc. nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package resolver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/noisysockets/netutil/addrselect"
	"github.com/noisysockets/resolver/internal/util"
	"golang.org/x/sync/errgroup"
)

var _ Resolver = (*dnsResolver)(nil)

// DNSTransport is the transport protocol used for DNS resolution.
type DNSTransport string

const (
	// DNSTransportUDP is DNS over UDP as defined in RFC 1035.
	DNSTransportUDP DNSTransport = "udp"
	// DNSTransportTCP is DNS over TCP as defined in RFC 1035.
	DNSTransportTCP DNSTransport = "tcp"
	// DNSTransportTLS is DNS over TLS as defined in RFC 7858.
	DNSTransportTLS DNSTransport = "tcp-tls"
)

// DNSResolverConfig is the configuration for a DNS resolver.
type DNSResolverConfig struct {
	// Server is the DNS server to query.
	Server netip.AddrPort
	// Transport is the optional transport protocol used for DNS resolution.
	// By default, plain DNS over UDP is used.
	Transport *DNSTransport
	// Timeout is the maximum duration to wait for a query to complete.
	Timeout *time.Duration
	// DialContext is used to establish a connection to a DNS server.
	DialContext DialContextFunc
	// TLSConfig is the configuration for the TLS client used for DNS over TLS.
	TLSConfig *tls.Config
	// SingleRequest is used to query A and AAAA records sequentially.
	// This is mostly useful for avoiding conntrack race issues with DNS over UDP.
	// If you feel the need to enable this, you should probably just use
	// DNS over TCP instead.
	SingleRequest *bool
}

// dnsResolver is a DNS resolver.
type dnsResolver struct {
	server        netip.AddrPort
	transport     DNSTransport
	timeout       time.Duration
	dialContext   DialContextFunc
	tlsConfig     *tls.Config
	singleRequest bool
}

// DNS creates a new DNS resolver.
func DNS(conf DNSResolverConfig) *dnsResolver {
	// Make sure the server port is set.
	server := conf.Server
	if server.Port() == 0 {
		if conf.Transport != nil && *conf.Transport == DNSTransportTLS {
			server = netip.AddrPortFrom(server.Addr(), 853)
		} else {
			server = netip.AddrPortFrom(server.Addr(), 53)
		}
	}

	withDefaults, err := util.ConfigWithDefaults(&conf, &DNSResolverConfig{
		Transport:   util.PointerTo(DNSTransportUDP),
		Timeout:     util.PointerTo(5 * time.Second),
		DialContext: (&net.Dialer{}).DialContext,
		TLSConfig: &tls.Config{
			ServerName: server.String(),
		},
		SingleRequest: util.PointerTo(false),
	})
	if err != nil {
		// Should never happen.
		panic(err)
	}
	conf = *withDefaults

	return &dnsResolver{
		server:        server,
		transport:     *conf.Transport,
		timeout:       *conf.Timeout,
		dialContext:   conf.DialContext,
		tlsConfig:     conf.TLSConfig,
		singleRequest: *conf.SingleRequest,
	}
}

func (r *dnsResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	dnsErr := &net.DNSError{
		Name: host,
	}

	// If the host is not a valid domain name, return an error.
	if _, ok := dns.IsDomainName(host); !ok {
		return nil, extendDNSError(dnsErr, net.DNSError{
			Err:        ErrNoSuchHost.Error(),
			IsNotFound: true,
		})
	}

	name := dns.Fqdn(host)

	var qTypes []uint16
	switch network {
	case "ip":
		qTypes = []uint16{dns.TypeA, dns.TypeAAAA}
	case "ip4":
		qTypes = []uint16{dns.TypeA}
	case "ip6":
		qTypes = []uint16{dns.TypeAAAA}
	default:
		return nil, extendDNSError(dnsErr, net.DNSError{
			Err: ErrUnsupportedNetwork.Error(),
		})
	}

	client := &dns.Client{
		Net:       string(r.transport),
		TLSConfig: r.tlsConfig,
		Timeout:   r.timeout,
	}

	var addrsMu sync.Mutex
	var addrs []netip.Addr

	tryOneNameAndAppendResults := func(ctx context.Context, qType uint16) error {
		reply, err := r.tryOneName(ctx, client, name, qType)
		if err != nil {
			return err
		}

		// We asked for recursion, so it should have included all the
		// answers we need in this one packet.
		//
		// Further, RFC 1034 section 4.3.1 says that "the recursive
		// response to a query will be... The answer to the query,
		// possibly preface by one or more CNAME RRs that specify
		// aliases encountered on the way to an answer."
		//
		// Therefore, we should be able to assume that we can ignore
		// CNAMEs and that the A and AAAA records we requested are
		// for the canonical name.

		addrsMu.Lock()
		defer addrsMu.Unlock()

		for _, rr := range reply.Answer {
			switch rr := rr.(type) {
			case *dns.A:
				addrs = append(addrs, netip.AddrFrom4([4]byte(rr.A.To4())))
			case *dns.AAAA:
				addrs = append(addrs, netip.AddrFrom16([16]byte(rr.AAAA.To16())))
			}
		}

		return nil
	}

	if r.singleRequest {
		for _, qType := range qTypes {
			if err := tryOneNameAndAppendResults(ctx, qType); err != nil {
				return nil, err
			}
		}
	} else {
		g, ctx := errgroup.WithContext(ctx)

		for _, qType := range qTypes {
			qType := qType
			g.Go(func() error {
				return tryOneNameAndAppendResults(ctx, qType)
			})
		}

		if err := g.Wait(); err != nil {
			return nil, err
		}
	}

	if len(addrs) > 0 {
		if network != "ip4" {
			dial := func(network, address string) (net.Conn, error) {
				return r.dialContext(ctx, network, address)
			}

			addrselect.SortByRFC6724(dial, addrs)
		}

		return addrs, nil
	}

	return nil, extendDNSError(dnsErr, net.DNSError{
		Err:        ErrNoSuchHost.Error(),
		IsNotFound: true,
	})
}

func (r *dnsResolver) tryOneName(ctx context.Context, client *dns.Client, name string, qType uint16) (*dns.Msg, *net.DNSError) {
	dnsErr := &net.DNSError{
		Name:   name,
		Server: r.server.String(),
	}

	if client.Timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, client.Timeout)
		defer cancel()
	}

	conn, err := r.dialContext(ctx, strings.TrimSuffix(client.Net, "-tls"), r.server.String())
	if err != nil {
		return nil, extendDNSError(dnsErr, net.DNSError{
			Err:         err.Error(),
			IsTimeout:   isTimeout(err),
			IsTemporary: true,
		})
	}

	if strings.HasSuffix(client.Net, "-tls") {
		conn = tls.Client(conn, r.tlsConfig)
		if err := conn.(*tls.Conn).HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			// Handshake errors are not likely to be temporary.
			return nil, extendDNSError(dnsErr, net.DNSError{
				Err:       err.Error(),
				IsTimeout: isTimeout(err),
			})
		}
	}
	defer conn.Close()

	req := &dns.Msg{}
	req.SetQuestion(name, qType)

	reply, _, err := client.ExchangeWithConn(req, &dns.Conn{Conn: conn})
	if err != nil {
		return nil, extendDNSError(dnsErr, net.DNSError{
			Err:         err.Error(),
			IsTimeout:   isTimeout(err),
			IsTemporary: true,
		})
	}

	switch reply.Rcode {
	case dns.RcodeSuccess:
		return reply, nil
	case dns.RcodeNameError:
		return nil, extendDNSError(dnsErr, net.DNSError{
			Err:        ErrNoSuchHost.Error(),
			IsNotFound: true,
		})
	default:
		return nil, extendDNSError(dnsErr, net.DNSError{
			Err: fmt.Errorf("unexpected return code %s: %w",
				dns.RcodeToString[reply.Rcode], ErrServerMisbehaving).Error(),
			// SERVFAIL is not cached.
			IsTemporary: reply.Rcode == dns.RcodeServerFailure,
		})
	}
}
