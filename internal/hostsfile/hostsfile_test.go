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
	require.Equal(t, firstRecord.Matches("foobar"), true)
	require.Equal(t, len(firstRecord.Hostnames), 1)

	require.Equal(t, h.records[1].comment, "# this is a comment")
	require.Equal(t, h.records[2].isBlank, true)

	aliasSample := "127.0.0.1 name alias1 alias2 alias3"
	h, err = Decode(strings.NewReader(aliasSample))
	require.NoError(t, err)
	hns := h.records[0].Hostnames
	require.Equal(t, len(hns), 4)
	require.Contains(t, hns, "alias3.")

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
	require.Contains(t, h.records[1].Hostnames, "2nd-alias.")

	h, err = Decode(strings.NewReader("##\n127.0.0.1\tlocalhost # a comment"))
	require.NoError(t, err)
	require.NotContains(t, h.records[0].Hostnames, "#.")
	require.NotContains(t, h.records[0].Hostnames, "a.")
}
