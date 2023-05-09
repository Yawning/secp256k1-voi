package secp256k1

import (
	"crypto/subtle"
	"errors"

	"gitlab.com/yawning/secp256k1-voi.git/internal/field"
	"gitlab.com/yawning/secp256k1-voi.git/internal/helpers"
)

// See: https://www.secg.org/sec1-v2.pdf
//
// There apparently is a "hybrid" format in X9.62 which is uncompressed
// but with the prefix encoding if y is odd or even.  However:
// - That's fucking moronic.
// - Not part of SEC 1.
// - A PDF copy of X9.62 costs 100 USD, assuming I don't get it from
// a domain that ends in `ru` or similar.
// - If you absolutely need to deal with a point in that format, it's
// trivial to convert to either of the supported encodings.

const (
	// CompressedPointSize is the size of a compressed point in bytes,
	// in the SEC 1, Version 2.0, Section 2.3.3 encoding (`Y_EvenOrOdd | X`).
	CompressedPointSize = 33

	// PointSize is the size of an uncompressed point in bytes in the
	// SEC 1, Version 2.0, Section 2.3.3 encoding (`0x04 | X | Y`).
	PointSize = 65

	// IdentityPointSize is the size of the point at infinity in bytes,
	// in the SEC 1, Version 2.0, Section 2.3.3 encoding (`0x00`).
	IdentityPointSize = 1

	// CoordSize is the size of a coordinate in bytes, in the SEC 1,
	// Version 2.0, Section 2.3.5 encoding.
	CoordSize = 32

	prefixIdentity       = 0x00
	prefixCompressedEven = 0x02
	prefixCompressedOdd  = 0x03
	prefixUncompressed   = 0x04
)

// feB is the constant `b`, part of the curve equation.
var feB = field.NewElementFromSaturated(0, 0, 0, 7)

// UncompressedBytes returns the SEC 1, Version 2.0, Section 2.3.3
// uncompressed encoding of `v`.
func (v *Point) UncompressedBytes() []byte {
	// Blah blah blah outline blah escape analysis blah.
	var dst [PointSize]byte
	return v.getUncompressedBytes(&dst)
}

func (v *Point) getUncompressedBytes(dst *[PointSize]byte) []byte {
	assertPointsValid(v)

	if v.IsIdentity() == 1 {
		return append(dst[:0], prefixIdentity)
	}

	scaled := newRcvr().rescale(v)

	buf := append(dst[:0], prefixUncompressed)
	buf = append(buf, scaled.x.Bytes()...)
	buf = append(buf, scaled.y.Bytes()...)

	return buf
}

// CompressedBytes returns the SEC 1, Version 2.0, Section 2.3.3
// compressed encoding of `v`.
func (v *Point) CompressedBytes() []byte {
	// Blah blah blah outline blah escape analysis blah.
	var dst [CompressedPointSize]byte
	return v.getCompressedBytes(&dst)
}

func (v *Point) getCompressedBytes(dst *[CompressedPointSize]byte) []byte {
	assertPointsValid(v)

	if v.IsIdentity() == 1 {
		return append(dst[:0], prefixIdentity)
	}

	scaled := newRcvr().rescale(v)

	y := subtle.ConstantTimeSelect(
		int(scaled.y.IsOdd()),
		prefixCompressedOdd,
		prefixCompressedEven,
	)

	buf := append(dst[:0], byte(y))
	buf = append(buf, scaled.x.Bytes()...)

	return buf
}

// XBytes returns the SEC 1, Version 2.0, Section 2.3.5 encoding of the
// x-coordinate, or an error if the point is the point at infinity.
func (v *Point) XBytes() ([]byte, error) {
	assertPointsValid(v)

	if v.IsIdentity() == 1 {
		return nil, errors.New("secp256k1: point is the point at infinity")
	}

	// Blah blah blah outline blah escape analysis blah.
	var dst [CoordSize]byte
	return v.getXBytes(&dst)
}

func (v *Point) getXBytes(dst *[CoordSize]byte) ([]byte, error) {
	scaled := newRcvr().rescale(v)
	return append(dst[:0], scaled.x.Bytes()...), nil
}

// SetBytes sets `p = src`, where `src` is a valid SEC 1, Version 2.0,
// Section 2.3.3 encoding of the point.  If `src` is not a valid
// encoding of `p`, SetBytes returns nil and an error, and the
// receiver is unchanged.
func (v *Point) SetBytes(src []byte) (*Point, error) {
	switch len(src) {
	case IdentityPointSize:
		if src[0] != prefixIdentity {
			break
		}

		v.Identity()
		return v, nil
	case CompressedPointSize:
		if src[0] != prefixCompressedOdd && src[0] != prefixCompressedEven {
			break
		}

		xBytes := (*[field.ElementSize]byte)(src[1:33])
		x, err := field.NewElementFromCanonicalBytes(xBytes)
		if err != nil {
			break
		}

		y, hasSqrt := field.NewElement().Sqrt(maybeYY(x))
		if hasSqrt != 1 {
			break
		}

		yNeg := field.NewElement().Negate(y)
		tagEq := subtle.ConstantTimeByteEq(byte(y.IsOdd()), src[0]&1)

		v.x.Set(x)
		v.y.ConditionalSelect(yNeg, y, helpers.Uint64IsNonzero(uint64(tagEq)))
		v.z.One()
		v.isValid = true

		return v, nil
	case PointSize:
		if src[0] != prefixUncompressed {
			break
		}

		xBytes := (*[field.ElementSize]byte)(src[1:33])
		x, err := field.NewElementFromCanonicalBytes(xBytes)
		if err != nil {
			break
		}
		yBytes := (*[field.ElementSize]byte)(src[33:65])
		y, err := field.NewElementFromCanonicalBytes(yBytes)
		if err != nil {
			break
		}

		// Check the points against the curve equation.
		if maybeYY(x).Equal(maybeXXXPlus7(y)) == 0 {
			break
		}

		v.x.Set(x)
		v.y.Set(y)
		v.z.One()
		v.isValid = true

		return v, nil
	}

	return nil, errors.New("secp256k1: malformed point encoding")
}

// NewPointFromBytes creates a new Point from either of the SEC 1
// encodings (uncompressed or compressed).
func NewPointFromBytes(src []byte) (*Point, error) {
	p, err := newRcvr().SetBytes(src)
	if err != nil {
		return nil, err
	}

	return p, nil
}

func maybeYY(x *field.Element) *field.Element {
	yy := field.NewElement().Square(x)
	yy.Multiply(yy, x)
	yy.Add(yy, feB)
	return yy
}

func maybeXXXPlus7(y *field.Element) *field.Element {
	return field.NewElement().Square(y)
}
