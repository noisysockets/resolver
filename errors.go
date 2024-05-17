// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package getresolvd

import "errors"

var (
	ErrNoSuchHost          = errors.New("no such host")
	ErrServerMisbehaving   = errors.New("server misbehaving")
	ErrUnsupportedNetwork  = errors.New("unsupported network")
	ErrUnsupportedProtocol = errors.New("unsupported protocol")
)
