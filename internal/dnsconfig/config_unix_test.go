//go:build unix

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
 * Copyright (c) 2024 The Go Authors. All rights reserved.
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

package dnsconfig

import (
	"errors"
	"io/fs"
	"os"
	"reflect"
	"testing"
	"time"
)

var dnsReadConfigTests = []struct {
	name string
	want *Config
}{
	{
		name: "testdata/resolv.conf",
		want: &Config{
			Servers:    []string{"8.8.8.8:53", "[2001:4860:4860::8888]:53", "[fe80::1%lo0]:53"},
			Search:     []string{"localdomain."},
			NDots:      5,
			Timeout:    10 * time.Second,
			Attempts:   3,
			Rotate:     true,
			UnknownOpt: true, // the "options attempts 3" line
		},
	},
	{
		name: "testdata/domain-resolv.conf",
		want: &Config{
			Servers:  []string{"8.8.8.8:53"},
			Search:   []string{"localdomain."},
			NDots:    1,
			Timeout:  5 * time.Second,
			Attempts: 2,
		},
	},
	{
		name: "testdata/search-resolv.conf",
		want: &Config{
			Servers:  []string{"8.8.8.8:53"},
			Search:   []string{"test.", "invalid."},
			NDots:    1,
			Timeout:  5 * time.Second,
			Attempts: 2,
		},
	},
	{
		name: "testdata/search-single-dot-resolv.conf",
		want: &Config{
			Servers:  []string{"8.8.8.8:53"},
			Search:   []string{},
			NDots:    1,
			Timeout:  5 * time.Second,
			Attempts: 2,
		},
	},
	{
		name: "testdata/empty-resolv.conf",
		want: &Config{
			Servers:  defaultNS,
			NDots:    1,
			Timeout:  5 * time.Second,
			Attempts: 2,
			Search:   []string{"domain.local."},
		},
	},
	{
		name: "testdata/invalid-ndots-resolv.conf",
		want: &Config{
			Servers:  defaultNS,
			NDots:    0,
			Timeout:  5 * time.Second,
			Attempts: 2,
			Search:   []string{"domain.local."},
		},
	},
	{
		name: "testdata/large-ndots-resolv.conf",
		want: &Config{
			Servers:  defaultNS,
			NDots:    15,
			Timeout:  5 * time.Second,
			Attempts: 2,
			Search:   []string{"domain.local."},
		},
	},
	{
		name: "testdata/negative-ndots-resolv.conf",
		want: &Config{
			Servers:  defaultNS,
			NDots:    0,
			Timeout:  5 * time.Second,
			Attempts: 2,
			Search:   []string{"domain.local."},
		},
	},
	{
		name: "testdata/openbsd-resolv.conf",
		want: &Config{
			NDots:    1,
			Timeout:  5 * time.Second,
			Attempts: 2,
			Lookup:   []string{"file", "bind"},
			Servers:  []string{"169.254.169.254:53", "10.240.0.1:53"},
			Search:   []string{"c.symbolic-datum-552.internal."},
		},
	},
	{
		name: "testdata/single-request-resolv.conf",
		want: &Config{
			Servers:       defaultNS,
			NDots:         1,
			SingleRequest: true,
			Timeout:       5 * time.Second,
			Attempts:      2,
			Search:        []string{"domain.local."},
		},
	},
	{
		name: "testdata/single-request-reopen-resolv.conf",
		want: &Config{
			Servers:       defaultNS,
			NDots:         1,
			SingleRequest: true,
			Timeout:       5 * time.Second,
			Attempts:      2,
			Search:        []string{"domain.local."},
		},
	},
	{
		name: "testdata/linux-use-vc-resolv.conf",
		want: &Config{
			Servers:  defaultNS,
			NDots:    1,
			UseTCP:   true,
			Timeout:  5 * time.Second,
			Attempts: 2,
			Search:   []string{"domain.local."},
		},
	},
	{
		name: "testdata/freebsd-usevc-resolv.conf",
		want: &Config{
			Servers:  defaultNS,
			NDots:    1,
			UseTCP:   true,
			Timeout:  5 * time.Second,
			Attempts: 2,
			Search:   []string{"domain.local."},
		},
	},
	{
		name: "testdata/openbsd-tcp-resolv.conf",
		want: &Config{
			Servers:  defaultNS,
			NDots:    1,
			UseTCP:   true,
			Timeout:  5 * time.Second,
			Attempts: 2,
			Search:   []string{"domain.local."},
		},
	},
}

func TestDNSReadConfig(t *testing.T) {
	origGetHostname := getHostname
	defer func() { getHostname = origGetHostname }()
	getHostname = func() (string, error) { return "host.domain.local", nil }

	for _, tt := range dnsReadConfigTests {
		want := *tt.want
		if len(want.Search) == 0 {
			want.Search = dnsDefaultSearch()
		}
		conf, err := Read(tt.name)
		if err != nil {
			t.Fatal(err)
		}
		conf.MTime = time.Time{}
		if !reflect.DeepEqual(conf, &want) {
			t.Errorf("%s:\ngot: %+v\nwant: %+v", tt.name, conf, want)
		}
	}
}

func TestDNSReadMissingFile(t *testing.T) {
	origGetHostname := getHostname
	defer func() { getHostname = origGetHostname }()
	getHostname = func() (string, error) { return "host.domain.local", nil }

	conf, err := Read("a-nonexistent-file")
	if !os.IsNotExist(err) {
		t.Errorf("missing resolv.conf:\ngot: %v\nwant: %v", err, fs.ErrNotExist)
	}
	want := &Config{
		Servers:  defaultNS,
		NDots:    1,
		Timeout:  5 * time.Second,
		Attempts: 2,
		Search:   []string{"domain.local."},
	}
	if !reflect.DeepEqual(conf, want) {
		t.Errorf("missing resolv.conf:\ngot: %+v\nwant: %+v", conf, want)
	}
}

var dnsDefaultSearchTests = []struct {
	name string
	err  error
	want []string
}{
	{
		name: "host.long.domain.local",
		want: []string{"long.domain.local."},
	},
	{
		name: "host.local",
		want: []string{"local."},
	},
	{
		name: "host",
		want: nil,
	},
	{
		name: "host.domain.local",
		err:  errors.New("errored"),
		want: nil,
	},
	{
		// ensures we don't return []string{""}
		// which causes duplicate lookups
		name: "foo.",
		want: nil,
	},
}

func TestDNSDefaultSearch(t *testing.T) {
	origGetHostname := getHostname
	defer func() { getHostname = origGetHostname }()

	for _, tt := range dnsDefaultSearchTests {
		getHostname = func() (string, error) { return tt.name, tt.err }
		got := dnsDefaultSearch()
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("dnsDefaultSearch with hostname %q and error %+v = %q, wanted %q", tt.name, tt.err, got, tt.want)
		}
	}
}
