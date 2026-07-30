//! Verifiable Random Function (`draft-ietf-keytrans-protocol-05` §11.7).
//!
//! Each label-version pair's search key in the prefix tree is the VRF output over
//! a [`VrfInput`](kt_wire::structs::VrfInput) (§11.7). That is what keeps labels
//! private: the tree is indexed by a value only the log can compute, so a user who
//! is handed a search key learns nothing about the label behind it, and — because
//! the VRF is *verifiable* — the log cannot use a different key for the same label
//! than the one it proves.
//!
//! One submodule per registered ciphersuite, mirroring both RFC 9381's structure
//! and the peer's `crypto/vrf/{edwards25519,p256}`:
//!
//! | Suite (§17.1) | Module | ECVRF ciphersuite | `VRF.Np` |
//! |---|---|---|---|
//! | `KT_128_SHA256_Ed25519` (`0x0002`) | [`edwards25519`] | `ECVRF-EDWARDS25519-SHA512-TAI` | 80 |
//! | `KT_128_SHA256_P256` (`0x0001`) | [`p256`] | `ECVRF-P256-SHA256-TAI` | 81 |
//!
//! [`Error`] and [`Output`] are shared, because a search key is 32 bytes in both
//! suites — §17.1 truncates edwards25519's 64-byte `beta_string` and takes P-256's
//! whole 32 — and because a caller that cannot parse a proof wants the same error
//! either way. Everything else differs: the curve, the hash, the integer byte
//! order, the encoded sizes.
//!
//! The keys and proofs are deliberately *not* unified behind one enum. A
//! `Configuration` fixes the suite for the whole log, so a caller knows which it
//! holds; a sum type would only move that knowledge to run time and invite reading
//! an 81-byte proof as an 80-byte one.

pub mod edwards25519;
pub mod p256;

use core::fmt;

use kt_wire::codec;
use kt_wire::structs::HashValue;

use crate::suite::CipherSuite;

/// Something wrong with a VRF key, proof, or the suite asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The cipher suite's VRF is not implemented here.
    ///
    /// Both registered suites are implemented, so this is only reachable if the
    /// registry gains a third.
    UnsupportedSuite {
        /// The suite that was asked for.
        suite: CipherSuite,
    },
    /// A public key was not a valid point on the suite's curve.
    MalformedPublicKey,
    /// A public key was of small order, so it commits to nothing.
    ///
    /// RFC 9381 §5.4.5 `ECVRF_validate_key`. Checked here because in this protocol
    /// the VRF public key arrives in a `Configuration` from the log, and a
    /// small-order key would let it produce the same output for every label. Only
    /// reachable for edwards25519: P-256 has prime order, so its only small-order
    /// element is the identity, which a valid SEC1 encoding cannot express.
    SmallOrderPublicKey,
    /// A proof was not `VRF.Np` bytes.
    ProofLength {
        /// `VRF.Np`.
        expected: usize,
        /// What was supplied.
        actual: usize,
    },
    /// A proof's `Gamma` was not a valid point on the suite's curve.
    MalformedGamma,
    /// A proof's `s` was not a canonical scalar, i.e. `s >= q`.
    ///
    /// RFC 9381 §5.4.4 step 7 requires rejecting these. Accepting them would make
    /// proofs malleable: several byte strings would verify for one signature. The
    /// peer's P-256 implementation additionally rejects `s == 0`; this does not,
    /// because zero is a canonical scalar and RFC 9381 asks only about `s >= q`.
    /// No honest prover emits it, so the difference is unreachable in practice.
    NonCanonicalScalar,
    /// The proof did not verify: the recomputed challenge differed.
    BadProof,
    /// A `VrfInput` could not be encoded, e.g. a label above the `2^8-1` ceiling.
    Wire(codec::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSuite { suite } => {
                write!(f, "the VRF for {suite} is not implemented")
            }
            Self::MalformedPublicKey => f.write_str("VRF public key is not a valid point"),
            Self::SmallOrderPublicKey => f.write_str("VRF public key is of small order"),
            Self::ProofLength { expected, actual } => {
                write!(f, "VRF proof must be {expected} bytes, got {actual}")
            }
            Self::MalformedGamma => f.write_str("VRF proof's Gamma is not a valid point"),
            Self::NonCanonicalScalar => f.write_str("VRF proof's s is not a canonical scalar"),
            Self::BadProof => f.write_str("VRF proof does not verify"),
            Self::Wire(err) => write!(f, "encoding the VRF input: {err}"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            // The wrapping variant has to be walkable, like the one in
            // `crate::Error` and `kt_tree::log::Error`: a caller that wants to know
            // *which* field of a VrfInput was too long should not have to parse the
            // rendered message to find out.
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

/// A specialized [`Result`] for VRF operations.
pub type Result<T> = core::result::Result<T, Error>;

/// A VRF output: the search key for a label-version pair (§11.7).
///
/// 32 bytes, which is `VRF.Nh` — the truncation §17.1 applies to ECVRF's 64-byte
/// `beta_string`. Only [`PublicKey::verify`] and [`SecretKey::evaluate`] produce
/// one, so an output can only exist alongside a proof that justifies it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Output(HashValue);

impl Output {
    /// Wraps a computed `beta_string`.
    ///
    /// Crate-internal on purpose: an `Output` should only ever come from a
    /// verification or an evaluation, so that holding one is evidence a proof
    /// justified it.
    pub(crate) const fn from_hash(hash: HashValue) -> Self {
        Self(hash)
    }
    /// The output as a prefix-tree search key.
    #[must_use]
    pub const fn search_key(&self) -> HashValue {
        self.0
    }

    /// The output bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; OUTPUT_SIZE] {
        self.0.as_bytes()
    }
}

/// `VRF.Nh` for both registered suites: the output length in bytes (§17.1).
///
/// RFC 9381's `beta_string` for this ciphersuite is 64 bytes; §17.1 specifies
/// "with the output truncated to 32 bytes", so that is what a search key is.
pub const OUTPUT_SIZE: usize = 32;
