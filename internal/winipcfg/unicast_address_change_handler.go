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

// UnicastAddressChangeCallback structure allows unicast address change callback handling.
type UnicastAddressChangeCallback struct {
	cb   func(notificationType MibNotificationType, unicastAddress *MibUnicastIPAddressRow)
	wait sync.WaitGroup
}

var (
	unicastAddressChangeAddRemoveMutex = sync.Mutex{}
	unicastAddressChangeMutex          = sync.Mutex{}
	unicastAddressChangeCallbacks      = make(map[*UnicastAddressChangeCallback]bool)
	unicastAddressChangeHandle         = windows.Handle(0)
)

// RegisterUnicastAddressChangeCallback registers a new UnicastAddressChangeCallback. If this particular callback is already
// registered, the function will silently return. Returned UnicastAddressChangeCallback.Unregister method should be used
// to unregister.
func RegisterUnicastAddressChangeCallback(callback func(notificationType MibNotificationType, unicastAddress *MibUnicastIPAddressRow)) (*UnicastAddressChangeCallback, error) {
	s := &UnicastAddressChangeCallback{cb: callback}

	unicastAddressChangeAddRemoveMutex.Lock()
	defer unicastAddressChangeAddRemoveMutex.Unlock()

	unicastAddressChangeMutex.Lock()
	defer unicastAddressChangeMutex.Unlock()

	unicastAddressChangeCallbacks[s] = true

	if unicastAddressChangeHandle == 0 {
		err := notifyUnicastIPAddressChange(windows.AF_UNSPEC, windows.NewCallback(unicastAddressChanged), 0, false, &unicastAddressChangeHandle)
		if err != nil {
			delete(unicastAddressChangeCallbacks, s)
			unicastAddressChangeHandle = 0
			return nil, err
		}
	}

	return s, nil
}

// Unregister unregisters the callback.
func (callback *UnicastAddressChangeCallback) Unregister() error {
	unicastAddressChangeAddRemoveMutex.Lock()
	defer unicastAddressChangeAddRemoveMutex.Unlock()

	unicastAddressChangeMutex.Lock()
	delete(unicastAddressChangeCallbacks, callback)
	removeIt := len(unicastAddressChangeCallbacks) == 0 && unicastAddressChangeHandle != 0
	unicastAddressChangeMutex.Unlock()

	callback.wait.Wait()

	if removeIt {
		err := cancelMibChangeNotify2(unicastAddressChangeHandle)
		if err != nil {
			return err
		}
		unicastAddressChangeHandle = 0
	}

	return nil
}

func unicastAddressChanged(callerContext uintptr, row *MibUnicastIPAddressRow, notificationType MibNotificationType) uintptr {
	rowCopy := *row
	unicastAddressChangeMutex.Lock()
	for cb := range unicastAddressChangeCallbacks {
		cb.wait.Add(1)
		go func(cb *UnicastAddressChangeCallback) {
			cb.cb(notificationType, &rowCopy)
			cb.wait.Done()
		}(cb)
	}
	unicastAddressChangeMutex.Unlock()
	return 0
}
