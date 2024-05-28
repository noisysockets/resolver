//go:build windows

// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions of this file are based on code originally from wireguard-windows,
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package winipcfg

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func runNetsh(cmds []string) error {
	system32, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	cmd := exec.Command(filepath.Join(system32, "netsh.exe"))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("runNetsh stdin pipe - %w", err)
	}
	go func() {
		defer stdin.Close()
		io.WriteString(stdin, strings.Join(append(cmds, "exit\r\n"), "\r\n"))
	}()
	output, err := cmd.CombinedOutput()
	// Horrible kludges, sorry.
	cleaned := bytes.ReplaceAll(output, []byte{'\r', '\n'}, []byte{'\n'})
	cleaned = bytes.ReplaceAll(cleaned, []byte("netsh>"), []byte{})
	cleaned = bytes.ReplaceAll(cleaned, []byte("There are no Domain Name Servers (DNS) configured on this computer."), []byte{})
	cleaned = bytes.TrimSpace(cleaned)
	if len(cleaned) != 0 && err == nil {
		return fmt.Errorf("netsh: %#q", string(cleaned))
	} else if err != nil {
		return fmt.Errorf("netsh: %v: %#q", err, string(cleaned))
	}
	return nil
}

const (
	netshCmdTemplateFlush4 = "interface ipv4 set dnsservers name=%d source=static address=none validate=no register=both"
	netshCmdTemplateFlush6 = "interface ipv6 set dnsservers name=%d source=static address=none validate=no register=both"
	netshCmdTemplateAdd4   = "interface ipv4 add dnsservers name=%d address=%s validate=no"
	netshCmdTemplateAdd6   = "interface ipv6 add dnsservers name=%d address=%s validate=no"
)

func (luid LUID) fallbackSetDNSForFamily(family AddressFamily, dnses []netip.Addr) error {
	var templateFlush string
	if family == windows.AF_INET {
		templateFlush = netshCmdTemplateFlush4
	} else if family == windows.AF_INET6 {
		templateFlush = netshCmdTemplateFlush6
	}

	cmds := make([]string, 0, 1+len(dnses))
	ipif, err := luid.IPInterface(family)
	if err != nil {
		return err
	}
	cmds = append(cmds, fmt.Sprintf(templateFlush, ipif.InterfaceIndex))
	for i := 0; i < len(dnses); i++ {
		if dnses[i].Is4() && family == windows.AF_INET {
			cmds = append(cmds, fmt.Sprintf(netshCmdTemplateAdd4, ipif.InterfaceIndex, dnses[i].String()))
		} else if dnses[i].Is6() && family == windows.AF_INET6 {
			cmds = append(cmds, fmt.Sprintf(netshCmdTemplateAdd6, ipif.InterfaceIndex, dnses[i].String()))
		}
	}
	return runNetsh(cmds)
}

func (luid LUID) fallbackSetDNSDomain(domain string) error {
	guid, err := luid.GUID()
	if err != nil {
		return fmt.Errorf("Error converting luid to guid: %w", err)
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, fmt.Sprintf("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Adapters\\%v", guid), registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("Error opening adapter-specific TCP/IP network registry key: %w", err)
	}
	paths, _, err := key.GetStringsValue("IpConfig")
	key.Close()
	if err != nil {
		return fmt.Errorf("Error reading IpConfig registry key: %w", err)
	}
	if len(paths) == 0 {
		return errors.New("No TCP/IP interfaces found on adapter")
	}
	key, err = registry.OpenKey(registry.LOCAL_MACHINE, fmt.Sprintf("SYSTEM\\CurrentControlSet\\Services\\%s", paths[0]), registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("Unable to open TCP/IP network registry key: %w", err)
	}
	err = key.SetStringValue("Domain", domain)
	key.Close()
	return err
}
