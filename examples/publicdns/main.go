// SPDX-License-Identifier: MIT

// Package main implements a simple example that resolves the IP addresses of
// google.com using Google's public DNS servers, and DNS over TLS.
package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/netip"
	"os"

	"github.com/noisysockets/resolver"
	"github.com/noisysockets/util/ptr"
)

func main() {
	logger := slog.Default()

	tlsConfig := tls.Config{
		ServerName: "dns.google",
	}

	res := resolver.Sequential(resolver.Literal(), resolver.RoundRobin(
		resolver.DNS(resolver.DNSResolverConfig{
			Server:    netip.MustParseAddrPort("8.8.8.8:853"),
			Transport: ptr.To(resolver.DNSTransportTLS),
			TLSConfig: &tlsConfig,
		}),
		resolver.DNS(resolver.DNSResolverConfig{
			Server:    netip.MustParseAddrPort("8.8.4.4:853"),
			Transport: ptr.To(resolver.DNSTransportTLS),
			TLSConfig: &tlsConfig,
		}),
	))

	ctx := context.Background()
	addrs, err := res.LookupNetIP(ctx, "ip", "google.com")
	if err != nil {
		logger.Error("Failed to resolve", slog.Any("error", err))
		os.Exit(1)
	}

	logger.Info("Resolved", slog.Any("addrs", addrs))
}
