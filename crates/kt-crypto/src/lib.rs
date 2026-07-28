//! Cryptographic primitives for IETF Key Transparency.
//!
//! Implements the cryptographic computations of `draft-ietf-keytrans-protocol`
//! §11.
//!
//! # Cipher suites (§11.1, registry in §17.1)
//!
//! | Value | Name | Signature | VRF |
//! |---|---|---|---|
//! | `0x0001` | `KT_128_SHA256_P256` | ECDSA / P-256 | ECVRF-P256-SHA256-TAI |
//! | `0x0002` | `KT_128_SHA256_Ed25519` | Ed25519 | ECVRF-EDWARDS25519-SHA512-TAI |
//!
//! Both use SHA-256, `Nc = 16` (commitment opening size), `Hash.Nh = 32`,
//! `VRF.Nh = 32`, and the fixed commitment key
//! `Kc = d821f8790d97709796b4d7903357c3f5`.
//!
//! `KT_128_SHA256_Ed25519` is implemented first: both Go peers support it and it
//! has fewer point-encoding traps than P-256.
//!
//! # Status
//!
//! [`commitment`] (§11.6) is implemented and pinned against the Go peer by
//! `interop/vectors/commitment.json`. [`vrf`] and [`signature`] are not
//! implemented yet.
//!
//! `UpdateValue` (§11.5) lives in `kt-wire` with the other protocol structs;
//! nothing about it is cryptographic beyond being the thing a commitment
//! commits to.

#![no_std]

extern crate alloc;

use core::fmt;

use kt_wire::codec;

pub mod commitment;
pub mod suite;

/// Verifiable Random Function over `VrfInput{label, version}`
/// (`draft-ietf-keytrans-protocol-05` §11.7).
pub mod vrf {
    // TODO(interop tier 1, step 3): ECVRF for both registered suites.
}

/// Tree head, auditor tree head, and full tree head signatures
/// (`draft-ietf-keytrans-protocol-05` §11.2, §11.3, §11.4).
pub mod signature {
    // TODO(interop tier 1, step 7).
}

/// A cryptographic computation failed, or was asked to operate on ill-formed
/// input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A value could not be encoded or decoded in the presentation language.
    Wire(codec::Error),
    /// A commitment opening was not `Nc` bytes (§11.6).
    OpeningLength {
        /// `Nc` for the suite in use.
        expected: usize,
        /// Length actually supplied.
        actual: usize,
    },
    /// A commitment was not `Hash.Nh` bytes.
    CommitmentLength {
        /// `Hash.Nh` for the suite in use.
        expected: usize,
        /// Length actually supplied.
        actual: usize,
    },
    /// A commitment did not open to the value it was checked against (§11.6).
    ///
    /// Carries no detail on purpose: which byte differed is not something a
    /// verifier should hand back to whoever supplied the commitment.
    CommitmentMismatch,
    /// The suite's `Kc` was rejected as an HMAC key.
    ///
    /// Unreachable for the suites in §17.1 — HMAC accepts keys of any length —
    /// and present so that no code path has to `unwrap`.
    CommitmentKeyLength,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(err) => write!(f, "wire encoding: {err}"),
            Self::OpeningLength { expected, actual } => {
                write!(
                    f,
                    "commitment opening must be {expected} bytes, got {actual}"
                )
            }
            Self::CommitmentLength { expected, actual } => {
                write!(f, "commitment must be {expected} bytes, got {actual}")
            }
            Self::CommitmentMismatch => f.write_str("commitment does not open to this value"),
            Self::CommitmentKeyLength => f.write_str("cipher suite Kc rejected as an HMAC key"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Wire(err) => Some(err),
            _ => None,
        }
    }
}

impl From<codec::Error> for Error {
    fn from(err: codec::Error) -> Self {
        Self::Wire(err)
    }
}
