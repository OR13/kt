//! Wire encoding for IETF Key Transparency.
//!
//! Implements the TLS presentation language subset of
//! `draft-ietf-keytrans-protocol` §2.1, and the protocol structs defined
//! throughout §11, §12, and §13.
//!
//! This crate is the bottom of the stack: it depends on no other crate in this
//! workspace, and every byte that crosses the wire is defined here. Encoding
//! bugs here are indistinguishable from protocol bugs everywhere above, so this
//! is the first thing to get under differential test against the Go
//! implementations — see `docs/interop.md`.
//!
//! # Scope
//!
//! §2.1.1 optional values, §2.1.2 variable-length vectors, and the fixed-size
//! opaque types; then the structs: `TreeHead` (§11.2), `AuditorTreeHead`
//! (§11.3), `FullTreeHead` (§11.4), `UpdateValue` (§11.5), `CommitmentValue`
//! (§11.6), `VrfInput` (§11.7), the proof types (§12), and the
//! request/response types (§13).
//!
//! # Invariants
//!
//! Every decoder takes adversary-controlled bytes. Decoding therefore always
//! returns [`codec::Result`], never panics, and never trusts a length prefix
//! without checking it against the remaining input.
//!
//! The crate is `no_std` (it needs `alloc` for `Vec`): nothing about encoding
//! bytes requires an operating system, and keeping it that way means a
//! misplaced `std` dependency shows up as a build error rather than as a
//! surprise for an embedded verifier.

#![no_std]

extern crate alloc;

pub mod codec;
pub mod heads;
pub mod proofs;
pub mod requests;
pub mod structs;

/// The draft revision this crate targets.
pub const DRAFT: &str = "draft-ietf-keytrans-protocol-05";
