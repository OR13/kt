// Vector generator for the kt Rust implementation.
//
// AGPL-3.0-only: this module links github.com/Bren2010/katie, which is
// AGPL-3.0. It is deliberately a separate module from the Cargo workspace so
// that boundary is structural. See ./LICENSE and ../../docs/licensing.md.
module github.com/OR13/kt/interop/go

go 1.24

require github.com/Bren2010/katie v0.0.0

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	filippo.io/nistec v0.0.3 // indirect
	github.com/golang/snappy v0.0.0-20180518054509-2e65f85255db // indirect
	github.com/syndtr/goleveldb v1.0.0 // indirect
)

// katie is consumed from the pinned submodule, never from the network.
replace github.com/Bren2010/katie => ../../upstream/katie
