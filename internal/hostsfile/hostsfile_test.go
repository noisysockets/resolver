// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions of this file are based on code originally:
 *
 * Copyright (c) 2014 Kevin Burke
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package hostsfile

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecode(t *testing.T) {
	t.Parallel()
	sampledata := "127.0.0.1 foobar\n# this is a comment\n\n10.0.0.1 anotheralias"
	h, err := Decode(strings.NewReader(sampledata))
	if err != nil {
		t.Error(err.Error())
	}
	firstRecord := h.records[0]

	require.Equal(t, firstRecord.IpAddress.IP.String(), "127.0.0.1")
	require.Equal(t, firstRecord.Hostnames["foobar"], true)
	require.Equal(t, len(firstRecord.Hostnames), 1)

	require.Equal(t, h.records[1].comment, "# this is a comment")
	require.Equal(t, h.records[2].isBlank, true)

	aliasSample := "127.0.0.1 name alias1 alias2 alias3"
	h, err = Decode(strings.NewReader(aliasSample))
	require.NoError(t, err)
	hns := h.records[0].Hostnames
	require.Equal(t, len(hns), 4)
	require.Equal(t, hns["alias3"], true)

	badline := strings.NewReader("blah")
	h, err = Decode(badline)
	if err == nil {
		t.Error("expected Decode(\"blah\") to return invalid, got no error")
	}
	if err.Error() != "invalid hostsfile entry: blah" {
		t.Errorf("expected Decode(\"blah\") to return invalid, got %s", err.Error())
	}

	h, err = Decode(strings.NewReader("##\n127.0.0.1\tlocalhost    2nd-alias"))
	require.NoError(t, err)
	require.Equal(t, h.records[1].Hostnames["2nd-alias"], true)

	h, err = Decode(strings.NewReader("##\n127.0.0.1\tlocalhost # a comment"))
	require.NoError(t, err)
	require.Equal(t, h.records[0].Hostnames["#"], false)
	require.Equal(t, h.records[0].Hostnames["a"], false)
}

func sample(t *testing.T) Hostsfile {
	one27, err := net.ResolveIPAddr("ip", "127.0.0.1")
	require.NoError(t, err)
	one92, err := net.ResolveIPAddr("ip", "192.168.0.1")
	require.NoError(t, err)
	oneip6, err := net.ResolveIPAddr("ip", "fe80::1%lo0")
	require.NoError(t, err)
	return Hostsfile{
		records: []*Record{
			{
				IpAddress: *one27,
				Hostnames: map[string]bool{"foobar": true},
			},
			{
				IpAddress: *one92,
				Hostnames: map[string]bool{"bazbaz": true, "blahbar": true},
			},
			{
				IpAddress: *oneip6,
				Hostnames: map[string]bool{"bazbaz": true},
			},
		},
	}
}

func comment(t *testing.T) Hostsfile {
	one92, err := net.ResolveIPAddr("ip", "192.168.0.1")
	require.NoError(t, err)
	return Hostsfile{
		records: []*Record{
			{
				comment: "# Don't delete this line!",
			},
			{
				comment: "shouldnt matter",
				isBlank: true,
			},
			{
				IpAddress: *one92,
				Hostnames: map[string]bool{"bazbaz": true},
			},
		},
	}
}

func TestEncode(t *testing.T) {
	t.Parallel()
	b := new(bytes.Buffer)
	err := Encode(b, sample(t))
	require.NoError(t, err)
	require.Equal(t, b.String(), "127.0.0.1 foobar\n192.168.0.1 bazbaz blahbar\nfe80::1%lo0 bazbaz\n")

	b.Reset()
	err = Encode(b, comment(t))
	require.NoError(t, err)
	require.Equal(t, b.String(), "# Don't delete this line!\n\n192.168.0.1 bazbaz\n")
}

func TestRemove(t *testing.T) {
	t.Parallel()
	hCopy := sample(t)
	require.Equal(t, len(hCopy.records[1].Hostnames), 2)
	hCopy.Remove("bazbaz")
	require.Equal(t, len(hCopy.records[1].Hostnames), 1)
	ok := hCopy.records[1].Hostnames["blahbar"]
	require.True(t, ok, fmt.Sprintf("item \"blahbar\" not found in %v", hCopy.records[1].Hostnames))
	hCopy.Remove("blahbar")
	require.Equal(t, len(hCopy.records), 1)
}

func TestProtocols(t *testing.T) {
	t.Parallel()
	one92, _ := net.ResolveIPAddr("ip", "192.168.3.7")
	ip6, _ := net.ResolveIPAddr("ip", "::1")
	require.Equal(t, matchProtocols(one92.IP, ip6.IP), false)
	require.Equal(t, matchProtocols(one92.IP, one92.IP), true)
	require.Equal(t, matchProtocols(ip6.IP, ip6.IP), true)
}

func TestSet(t *testing.T) {
	t.Parallel()
	hCopy := sample(t)
	one0, err := net.ResolveIPAddr("ip", "10.0.0.1")
	require.NoError(t, err)
	require.NoError(t, hCopy.Set(*one0, "tendot"))
	require.Equal(t, len(hCopy.records), 4)
	require.Equal(t, hCopy.records[3].Hostnames["tendot"], true)
	require.Equal(t, hCopy.records[3].IpAddress.String(), "10.0.0.1")

	// appending same element shouldn't change anything
	require.NoError(t, hCopy.Set(*one0, "tendot"))
	require.Equal(t, len(hCopy.records), 4)

	one92, err := net.ResolveIPAddr("ip", "192.168.3.7")
	require.NoError(t, err)
	require.NoError(t, hCopy.Set(*one92, "tendot"))
	require.Equal(t, hCopy.records[3].IpAddress.String(), "192.168.3.7")

	ip6, err := net.ResolveIPAddr("ip", "::1")
	require.NoError(t, err)
	require.NoError(t, hCopy.Set(*ip6, "tendot"))
	require.Equal(t, len(hCopy.records), 5)
	require.Equal(t, hCopy.records[4].IpAddress.String(), "::1")
}
