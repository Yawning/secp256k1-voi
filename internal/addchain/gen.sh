#!/bin/sh
#
# (Re)generate addchain artifacts
#
# This requires addchain (e40ce6aef373db2e2eb814c3345606ba221b6fb7) and
# gofumpt to be in the path.
#

# secp256k1 field inversion
rm -f field_invert.acc ../field/field_invert.go
addchain search "2^256 - 2^32 - 977 - 2" > field_invert.acc
addchain gen -tmpl field_invert.tmpl field_invert.acc > ../field/field_invert.go
gofumpt -w ../field/field_invert.go

# sec256k1 field sqrt_ratio
#
# From sage:
# (p-3)/4 = ((2^256 - 2^32 - 977) - 3) / 4
#         = 28948022309329048855892746252171976963317496166410141009864396001977208667915
rm -f field_pow_c1.acc ../field/field_pow_c1.acc
addchain search "28948022309329048855892746252171976963317496166410141009864396001977208667915" > field_pow_c1.acc
addchain gen -tmpl field_sqrt_ratio.tmpl field_pow_c1.acc > ../field/field_sqrt_ratio.go
gofumpt -w ../field/field_sqrt_ratio.go

# secp256k1 scalar inversion
rm -f scalar_invert.acc
addchain search "2^256 - 432420386565659656852420866394968145599 - 2" > scalar_invert.acc
addchain gen -tmpl scalar_invert.tmpl scalar_invert.acc > ../../scalar_invert.go
gofumpt -w ../../scalar_invert.go
