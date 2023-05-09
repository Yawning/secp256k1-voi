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
