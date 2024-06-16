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
	"bufio"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
)

// Represents a hosts file. Records match a single line in the file.
type Hostsfile struct {
	records []*Record
}

// Records returns an array of all entries in the hostsfile.
func (h *Hostsfile) Records() []*Record {
	return h.records
}

// A single line in the hosts file
type Record struct {
	IpAddress net.IPAddr
	Hostnames map[string]bool
	comment   string
	isBlank   bool
	mu        sync.Mutex
}

// returns true if a and b are not both ipv4 addresses
func matchProtocols(a, b net.IP) bool {
	ato4 := a.To4()
	bto4 := b.To4()
	return (ato4 == nil && bto4 == nil) ||
		(ato4 != nil && bto4 != nil)
}

// Adds a record to the list. If the hostname is present with a different IP
// address, it will be reassigned. If the record is already present with the
// same hostname/IP address data, it will not be added again.
func (h *Hostsfile) Set(ipa net.IPAddr, hostname string) error {
	addKey := true
	for i := 0; i < len(h.records); i++ {
		record := h.records[i]
		record.mu.Lock()
		_, ok := record.Hostnames[hostname]
		if ok {
			if record.IpAddress.IP.Equal(ipa.IP) {
				// tried to set a key that exists with the same IP address,
				// nothing to do
				addKey = false
			} else {
				// if the protocol matches, delete the key and be sure to add
				// a new record.
				if matchProtocols(record.IpAddress.IP, ipa.IP) {
					delete(record.Hostnames, hostname)
					if len(record.Hostnames) == 0 {
						// delete the record
						h.records = append(h.records[:i], h.records[i+1:]...)
					}
					addKey = true
				}
			}
		}
		record.mu.Unlock()
	}

	if addKey {
		nr := &Record{
			IpAddress: ipa,
			Hostnames: map[string]bool{hostname: true},
		}
		h.records = append(h.records, nr)
	}
	return nil
}

// Removes all references to hostname from the file. Returns false if the
// record was not found in the file.
func (h *Hostsfile) Remove(hostname string) (found bool) {
	for i := len(h.records) - 1; i >= 0; i-- {
		record := h.records[i]
		record.mu.Lock()
		if _, ok := record.Hostnames[hostname]; ok {
			delete(record.Hostnames, hostname)
			if len(record.Hostnames) == 0 {
				// delete the record
				if i == len(h.records)-1 {
					h.records = h.records[:len(h.records)-1]
				} else {
					h.records = append(h.records[:i], h.records[i+1:]...)
				}
			}
			found = true
		}
		record.mu.Unlock()
	}
	return
}

// Decodes the raw text of a hostsfile into a Hostsfile struct. If a line
// contains both an IP address and a comment, the comment will be lost.
//
// Interface example from the image package.
func Decode(rdr io.Reader) (Hostsfile, error) {
	var h Hostsfile
	scanner := bufio.NewScanner(rdr)
	for scanner.Scan() {
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)
		r := new(Record)
		if len(line) == 0 {
			r.isBlank = true
		} else if line[0] == '#' {
			// comment line or blank line: skip it.
			r.comment = line
		} else {
			vals := strings.Fields(line)
			if len(vals) <= 1 {
				return Hostsfile{}, fmt.Errorf("invalid hostsfile entry: %s", line)
			}
			ip, err := net.ResolveIPAddr("ip", vals[0])
			if err != nil {
				return Hostsfile{}, err
			}
			r = &Record{
				IpAddress: *ip,
				Hostnames: map[string]bool{},
			}
			for i := 1; i < len(vals); i++ {
				name := vals[i]
				if len(name) > 0 && name[0] == '#' {
					// beginning of a comment. rest of the line is bunk
					break
				}
				r.Hostnames[name] = true
			}
		}
		h.records = append(h.records, r)
	}
	if err := scanner.Err(); err != nil {
		return Hostsfile{}, err
	}
	return h, nil
}

// Return the text representation of the hosts file.
func Encode(w io.Writer, h Hostsfile) error {
	for _, record := range h.records {
		var toWrite string
		if record.isBlank {
			toWrite = ""
		} else if len(record.comment) > 0 {
			toWrite = record.comment
		} else {
			out := make([]string, len(record.Hostnames))
			i := 0
			for name := range record.Hostnames {
				out[i] = name
				i++
			}
			sort.Strings(out)
			out = append([]string{record.IpAddress.String()}, out...)
			toWrite = strings.Join(out, " ")
		}
		toWrite += eol
		_, err := w.Write([]byte(toWrite))
		if err != nil {
			return err
		}
	}
	return nil
}
