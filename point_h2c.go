// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: BSD-3-Clause

package secp256k1

import (
	"gitlab.com/yawning/secp256k1-voi/internal/field"
	"gitlab.com/yawning/secp256k1-voi/internal/swu"
)

// SetUniformBytes sets `v = map_to_curve(OS2IP(src) mod p)`, where
// `src` MUST be have a length in the range `[32,64]`-bytes, and
// returns `v`.  If called with exactly 48-bytes of data, this can
// be used to implement `encode_to_curve` and `hash_to_curve`.
// With a cryptographically insignificant probability, the result MAY
// be the point at infinity.
//
// Most users SHOULD use a higher-level `encode_to_curve` or
// `hash_to_curve` implementation instead.
func (v *Point) SetUniformBytes(src []byte) *Point {
	// The IETF draft notes that there is an optimization opportunity
	// for the random oracle suites to save a call to `iso_map` by
	// doing the point addition in E'.
	//
	// This seems marginal at best, and it 100% is not worth carrying
	// around the generic (non-specialized) point addition formula.

	u := field.NewElement().SetWideBytes(src)

	// 6.6.3. Simplified SWU for AB == 0

	// 1. (x', y') = map_to_curve_simple_swu(u)    # (x', y') is on E'
	xP, yP := swu.MapToCurveSimpleSWU(u)

	// 2. (x, y) = iso_map(x', y')               # (x, y) is on E
	x, y, isOnCurve := swu.IsoMap(xP, yP)

	// 3. return (x, y)
	v.x.Set(x)
	v.y.Set(y)
	v.z.One()
	v.isValid = true

	// map_to_curve_simple_swu handles its exceptional cases.
	// Exceptional cases of iso_map are inputs that cause the
	// denominator of either rational function to evaluate to zero;
	// such cases MUST return the identity point on E.
	v.ConditionalSelect(NewIdentityPoint(), v, isOnCurve)

	return v
}
