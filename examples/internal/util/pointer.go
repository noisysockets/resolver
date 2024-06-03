// SPDX-License-Identifier: MIT

package util

// PointerTo returns a pointer to the value v.
func PointerTo[T any](v T) *T {
	return &v
}
