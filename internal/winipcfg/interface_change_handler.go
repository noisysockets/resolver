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
	"sync"

	"golang.org/x/sys/windows"
)

// InterfaceChangeCallback structure allows interface change callback handling.
type InterfaceChangeCallback struct {
	cb   func(notificationType MibNotificationType, iface *MibIPInterfaceRow)
	wait sync.WaitGroup
}

var (
	interfaceChangeAddRemoveMutex = sync.Mutex{}
	interfaceChangeMutex          = sync.Mutex{}
	interfaceChangeCallbacks      = make(map[*InterfaceChangeCallback]bool)
	interfaceChangeHandle         = windows.Handle(0)
)

// RegisterInterfaceChangeCallback registers a new InterfaceChangeCallback. If this particular callback is already
// registered, the function will silently return. Returned InterfaceChangeCallback.Unregister method should be used
// to unregister.
func RegisterInterfaceChangeCallback(callback func(notificationType MibNotificationType, iface *MibIPInterfaceRow)) (*InterfaceChangeCallback, error) {
	s := &InterfaceChangeCallback{cb: callback}

	interfaceChangeAddRemoveMutex.Lock()
	defer interfaceChangeAddRemoveMutex.Unlock()

	interfaceChangeMutex.Lock()
	defer interfaceChangeMutex.Unlock()

	interfaceChangeCallbacks[s] = true

	if interfaceChangeHandle == 0 {
		err := notifyIPInterfaceChange(windows.AF_UNSPEC, windows.NewCallback(interfaceChanged), 0, false, &interfaceChangeHandle)
		if err != nil {
			delete(interfaceChangeCallbacks, s)
			interfaceChangeHandle = 0
			return nil, err
		}
	}

	return s, nil
}

// Unregister unregisters the callback.
func (callback *InterfaceChangeCallback) Unregister() error {
	interfaceChangeAddRemoveMutex.Lock()
	defer interfaceChangeAddRemoveMutex.Unlock()

	interfaceChangeMutex.Lock()
	delete(interfaceChangeCallbacks, callback)
	removeIt := len(interfaceChangeCallbacks) == 0 && interfaceChangeHandle != 0
	interfaceChangeMutex.Unlock()

	callback.wait.Wait()

	if removeIt {
		err := cancelMibChangeNotify2(interfaceChangeHandle)
		if err != nil {
			return err
		}
		interfaceChangeHandle = 0
	}

	return nil
}

func interfaceChanged(callerContext uintptr, row *MibIPInterfaceRow, notificationType MibNotificationType) uintptr {
	rowCopy := *row
	interfaceChangeMutex.Lock()
	for cb := range interfaceChangeCallbacks {
		cb.wait.Add(1)
		go func(cb *InterfaceChangeCallback) {
			cb.cb(notificationType, &rowCopy)
			cb.wait.Done()
		}(cb)
	}
	interfaceChangeMutex.Unlock()
	return 0
}
