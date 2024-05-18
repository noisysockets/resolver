// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package resolver_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/noisysockets/resolver"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestDefaultResolver(t *testing.T) {
	res := resolver.Default

	t.Run("LookupHost", func(t *testing.T) {
		// Lookup a domain where we know the IP addresses.
		addrs, err := res.LookupHost(context.Background(), "10.0.0.1.nip.io")
		require.NoError(t, err)

		require.Equal(t, []string{"10.0.0.1"}, addrs)
	})
}

func TestGoResolver(t *testing.T) {
	dnsReq := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context: "testdata",
		},
		ExposedPorts: []string{"53/tcp", "53/udp", "853/tcp"},
		WaitingFor:   wait.ForListeningPort("53/tcp"),
	}

	ctx := context.Background()
	dnsC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: dnsReq,
		Started:          true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, dnsC.Terminate(ctx))
	})

	// Get the dns server address / port
	dnsHost, err := dnsC.Host(ctx)
	require.NoError(t, err)

	dnsAddrs, err := net.LookupHost(dnsHost)
	require.NoError(t, err)

	// Bind startup can be a bit unpredictable.
	time.Sleep(3 * time.Second)

	t.Parallel()

	t.Run("UDP", func(t *testing.T) {
		dnsMappedPort, err := dnsC.MappedPort(ctx, "53/udp")
		require.NoError(t, err)

		res := resolver.DNS(&resolver.DNSResolverConfig{
			Protocol: resolver.ProtocolUDP,
			Servers: []netip.AddrPort{
				netip.AddrPortFrom(netip.MustParseAddr(dnsAddrs[0]), uint16(dnsMappedPort.Int())),
			},
		})

		t.Run("LookupHost", func(t *testing.T) {
			addrs, err := res.LookupHost(ctx, "www1.example.my.nzzy.net")
			require.NoError(t, err)

			require.Equal(t, []string{"192.168.1.2", "2001:db8::1"}, addrs)
		})
	})

	t.Run("TCP", func(t *testing.T) {
		dnsMappedPort, err := dnsC.MappedPort(ctx, "53/tcp")
		require.NoError(t, err)

		res := resolver.DNS(&resolver.DNSResolverConfig{
			Protocol: resolver.ProtocolTCP,
			Servers: []netip.AddrPort{
				netip.AddrPortFrom(netip.MustParseAddr(dnsAddrs[0]), uint16(dnsMappedPort.Int())),
			},
		})

		t.Run("LookupHost", func(t *testing.T) {
			addrs, err := res.LookupHost(ctx, "www1.example.my.nzzy.net")
			require.NoError(t, err)

			require.Equal(t, []string{"192.168.1.2", "2001:db8::1"}, addrs)
		})
	})

	t.Run("TLS", func(t *testing.T) {
		dnsMappedPort, err := dnsC.MappedPort(ctx, "853/tcp")
		require.NoError(t, err)

		// Trust the self signed CA certificate.
		caCertPEM, err := os.ReadFile("testdata/pki/ca.pem")
		require.NoError(t, err)

		caCertBytes, _ := pem.Decode(caCertPEM)
		caCert, err := x509.ParseCertificate(caCertBytes.Bytes)
		require.NoError(t, err)

		rootCAs := x509.NewCertPool()
		rootCAs.AddCert(caCert)

		res := resolver.DNS(&resolver.DNSResolverConfig{
			Protocol: resolver.ProtocolTLS,
			Servers: []netip.AddrPort{
				netip.AddrPortFrom(netip.MustParseAddr(dnsAddrs[0]), uint16(dnsMappedPort.Int())),
			},
			TLSClientConfig: &tls.Config{
				RootCAs: rootCAs,
			},
		})

		addrs, err := res.LookupHost(ctx, "www1.example.my.nzzy.net")
		require.NoError(t, err)

		require.Equal(t, []string{"192.168.1.2", "2001:db8::1"}, addrs)
	})
}
