#!/bin/sh
#
# (Re)generate avo artifacts
#

rm -f ../../point_mul_table_amd64.s
go run gen_table_amd64.go > ../../point_mul_table_amd64.s
