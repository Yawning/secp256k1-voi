// Copyright 2023 Yawning Angel.  All Rights Reserved.
//
// secp256k1-voi can be used in non-commercial projects of any kind,
// excluding those relating to or containing non-fungible tokens
// ("NFT") or blockchain-related projects.
//
// The package can not be modified to suit your needs. You may not
// redistribute or resell it, even if modified.

// Package disalloweq provides a method for disallowing struct comparisons
// with the `==` operator.
package disalloweq

// DisallowEqual can be used to cause the compiler to reject attempts to
// compare structs with the `==` operator.
//
// The better solution would be for Go to embrace circa 1960s technology
// and support operator overloading a la ALGOL 68.
//
// See: https://twitter.com/bradfitz/status/860145039573385216
type DisallowEqual [0]func()
