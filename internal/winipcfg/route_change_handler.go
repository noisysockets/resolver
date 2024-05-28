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

// RouteChangeCallback structure allows route change callback handling.
type RouteChangeCallback struct {
	cb   func(notificationType MibNotificationType, route *MibIPforwardRow2)
	wait sync.WaitGroup
}

var (
	routeChangeAddRemoveMutex = sync.Mutex{}
	routeChangeMutex          = sync.Mutex{}
	routeChangeCallbacks      = make(map[*RouteChangeCallback]bool)
	routeChangeHandle         = windows.Handle(0)
)

// RegisterRouteChangeCallback registers a new RouteChangeCallback. If this particular callback is already
// registered, the function will silently return. Returned RouteChangeCallback.Unregister method should be used
// to unregister.
func RegisterRouteChangeCallback(callback func(notificationType MibNotificationType, route *MibIPforwardRow2)) (*RouteChangeCallback, error) {
	s := &RouteChangeCallback{cb: callback}

	routeChangeAddRemoveMutex.Lock()
	defer routeChangeAddRemoveMutex.Unlock()

	routeChangeMutex.Lock()
	defer routeChangeMutex.Unlock()

	routeChangeCallbacks[s] = true

	if routeChangeHandle == 0 {
		err := notifyRouteChange2(windows.AF_UNSPEC, windows.NewCallback(routeChanged), 0, false, &routeChangeHandle)
		if err != nil {
			delete(routeChangeCallbacks, s)
			routeChangeHandle = 0
			return nil, err
		}
	}

	return s, nil
}

// Unregister unregisters the callback.
func (callback *RouteChangeCallback) Unregister() error {
	routeChangeAddRemoveMutex.Lock()
	defer routeChangeAddRemoveMutex.Unlock()

	routeChangeMutex.Lock()
	delete(routeChangeCallbacks, callback)
	removeIt := len(routeChangeCallbacks) == 0 && routeChangeHandle != 0
	routeChangeMutex.Unlock()

	callback.wait.Wait()

	if removeIt {
		err := cancelMibChangeNotify2(routeChangeHandle)
		if err != nil {
			return err
		}
		routeChangeHandle = 0
	}

	return nil
}

func routeChanged(callerContext uintptr, row *MibIPforwardRow2, notificationType MibNotificationType) uintptr {
	rowCopy := *row
	routeChangeMutex.Lock()
	for cb := range routeChangeCallbacks {
		cb.wait.Add(1)
		go func(cb *RouteChangeCallback) {
			cb.cb(notificationType, &rowCopy)
			cb.wait.Done()
		}(cb)
	}
	routeChangeMutex.Unlock()
	return 0
}
