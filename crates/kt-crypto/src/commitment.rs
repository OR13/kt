//! Commitments — `HMAC(Kc, CommitmentValue)`
//! (`draft-ietf-keytrans-protocol-05` §11.6).
//!
//! The leaves of the prefix tree hold commitments that open to the value of a
//! label-version pair (§11.5). §11.6 defines the commitment as
//!
//! ```pseudocode
//! commitment = HMAC(Kc, CommitmentValue)
//! ```
//!
//! where `Kc` is fixed by the cipher suite, the HMAC hash is the suite's hash,
//! and `CommitmentValue` is the presentation-language encoding of
//! `{opening, label, version, update}`. Note that `Kc` is a *published
//! constant*, not a secret: HMAC is used here as a commitment scheme, so the
//! security property being relied on is that it is computationally binding and
//! hiding, not that the key is unknown.
//!
//! # Interop note
//!
//! The draft places `opaque opening[Nc]` inside `CommitmentValue`; the Go peer
//! `katie` keeps `opening` outside its struct and writes it to the HMAC before
//! the serialized remainder. The hashed bytes are identical — the difference is
//! only where the field lives — and `interop/vectors/commitment.json` records
//! both the full `CommitmentValue` encoding and the resulting commitment, so the
//! two factorings are pinned against each other. This crate follows the draft.

use hmac::{Hmac, KeyInit, Mac};
use kt_wire::codec::{self, Encode as _};
use kt_wire::structs::CommitmentValue;
use sha2::Sha256;

use crate::Error;
use crate::suite::{CipherSuite, NH};

/// A commitment: `Hash.Nh` bytes of HMAC output.
///
/// The right way to check a commitment is [`verify`], which recomputes it from
/// the opening. [`PartialEq`] is implemented in constant time so that comparing
/// two commitments directly — which the interop tests do — cannot become a
/// timing oracle for a matching prefix.
#[derive(Copy, Clone, Debug)]
pub struct Commitment([u8; NH]);

impl PartialEq for Commitment {
    fn eq(&self, other: &Self) -> bool {
        // Bitwise accumulation: no early exit, so the running time does not
        // depend on where the first differing byte is.
        let mut diff = 0_u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

impl Eq for Commitment {}

impl Commitment {
    /// Wraps `Nh` bytes received from the wire or a test vector.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NH]) -> Self {
        Self(bytes)
    }

    /// Wraps a byte slice that must be exactly `Nh` long.
    ///
    /// # Errors
    ///
    /// [`Error::CommitmentLength`] if `bytes` is not `Nh` bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let array = <[u8; NH]>::try_from(bytes).map_err(|_| Error::CommitmentLength {
            expected: NH,
            actual: bytes.len(),
        })?;
        Ok(Self(array))
    }

    /// The commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NH] {
        &self.0
    }
}

/// Computes `HMAC(Kc, CommitmentValue)` for `value` under `suite` (§11.6).
///
/// The caller supplies the `opening` inside `value`; §11.6 requires it to be
/// `Nc` random bytes, or derived so as to be indistinguishable from random.
///
/// # Errors
///
/// - [`Error::OpeningLength`] if `value.opening` is not `suite.nc()` bytes. The
///   opening is a fixed-size `opaque opening[Nc]` with no length prefix, so a
///   wrong length silently shifts every following field; it is caught here
///   rather than becoming a mysterious mismatch.
/// - [`Error::Wire`] if `value` cannot be encoded, e.g. a label longer than the
///   `2^8-1` ceiling in §11.6.
pub fn commit(suite: CipherSuite, value: &CommitmentValue) -> Result<Commitment, Error> {
    let bytes = encode_commitment_value(suite, value)?;
    let mut mac = new_mac(suite)?;
    mac.update(&bytes);
    Ok(Commitment(mac.finalize().into_bytes().into()))
}

/// Checks that `value` opens `commitment` (§11.6).
///
/// The tag comparison is the constant-time one from the `hmac` crate. It is not
/// a secret-dependent comparison in the usual sense — both sides are public —
/// but a non-constant-time check here would leak a matching-prefix oracle to
/// anyone able to submit candidate openings, so there is no reason to accept it.
///
/// # Errors
///
/// [`Error::CommitmentMismatch`] if `value` does not open `commitment`, plus the
/// same encoding errors as [`commit`].
pub fn verify(
    suite: CipherSuite,
    value: &CommitmentValue,
    commitment: &Commitment,
) -> Result<(), Error> {
    let bytes = encode_commitment_value(suite, value)?;
    let mut mac = new_mac(suite)?;
    mac.update(&bytes);
    mac.verify_slice(commitment.as_bytes())
        .map_err(|_| Error::CommitmentMismatch)
}

/// Encodes a `CommitmentValue` after checking it against the suite (§11.6).
///
/// Exposed because the encoding is exactly the byte string that gets HMAC'd, and
/// the interop vectors pin it independently of the HMAC output — a mismatch in
/// the encoding and a mismatch in the MAC are different bugs and should not be
/// diagnosed as one.
///
/// # Errors
///
/// [`Error::OpeningLength`] or [`Error::Wire`], as for [`commit`].
pub fn encode_commitment_value(
    suite: CipherSuite,
    value: &CommitmentValue,
) -> Result<alloc::vec::Vec<u8>, Error> {
    if value.opening.len() != suite.nc() {
        return Err(Error::OpeningLength {
            expected: suite.nc(),
            actual: value.opening.len(),
        });
    }
    let mut enc = codec::Encoder::new();
    value.encode(&mut enc)?;
    Ok(enc.into_bytes())
}

/// Builds the HMAC instance the suite calls for.
fn new_mac(suite: CipherSuite) -> Result<Hmac<Sha256>, Error> {
    match suite {
        // Both registered suites hash with SHA-256 (§17.1). A future suite with
        // a different hash must add an arm here rather than fall through.
        CipherSuite::Kt128Sha256P256 | CipherSuite::Kt128Sha256Ed25519 => {
            // HMAC accepts keys of any length, so this cannot fail for the
            // 16-byte Kc; it is still propagated rather than unwrapped.
            Hmac::<Sha256>::new_from_slice(suite.kc()).map_err(|_| Error::CommitmentKeyLength)
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail loudly by panicking; the lint protects library paths"
)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use kt_wire::structs::UpdateValue;

    const SUITE: CipherSuite = CipherSuite::Kt128Sha256Ed25519;

    fn sample() -> CommitmentValue {
        CommitmentValue {
            opening: (0x10..0x20).collect(),
            label: b"alice@example.com".to_vec(),
            version: 0,
            update: UpdateValue::new(b"key-material-1".to_vec()),
        }
    }

    #[test]
    fn commitment_verifies_against_itself() {
        let value = sample();
        let commitment = commit(SUITE, &value).unwrap();
        verify(SUITE, &value, &commitment).unwrap();
    }

    /// The negative case from `interop/vectors/commitment.json`: flipping a bit
    /// in the opening must not verify.
    #[test]
    fn wrong_opening_does_not_verify() {
        let value = sample();
        let commitment = commit(SUITE, &value).unwrap();

        let mut tampered = value.clone();
        tampered.opening = value.opening.clone();
        let first = tampered.opening.first_mut().unwrap();
        *first ^= 0x01;

        assert_eq!(
            verify(SUITE, &tampered, &commitment),
            Err(Error::CommitmentMismatch)
        );
    }

    /// Each field is bound: changing any one of them changes the commitment.
    #[test]
    fn every_field_is_bound() {
        let base = sample();
        let commitment = commit(SUITE, &base).unwrap();

        let mut different_label = base.clone();
        different_label.label = b"bob@example.com".to_vec();

        let mut different_version = base.clone();
        different_version.version = 1;

        let mut different_value = base.clone();
        different_value.update = UpdateValue::new(b"key-material-2".to_vec());

        for candidate in [different_label, different_version, different_value] {
            assert_eq!(
                verify(SUITE, &candidate, &commitment),
                Err(Error::CommitmentMismatch)
            );
        }
    }

    /// A label and a value can be shuffled between fields without changing the
    /// concatenation of their contents; the length prefixes are what stop that
    /// from being a second valid opening of the same commitment.
    #[test]
    fn length_prefixes_prevent_field_confusion() {
        let opening: Vec<u8> = vec![0_u8; 16];
        let first = CommitmentValue {
            opening: opening.clone(),
            label: b"ab".to_vec(),
            version: 0,
            update: UpdateValue::new(b"cd".to_vec()),
        };
        let second = CommitmentValue {
            opening,
            label: b"abcd".to_vec(),
            version: 0,
            update: UpdateValue::new(Vec::new()),
        };
        let a = commit(SUITE, &first).unwrap();
        let b = commit(SUITE, &second).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn opening_must_be_nc_bytes() {
        let mut short = sample();
        short.opening.pop();
        assert_eq!(
            commit(SUITE, &short),
            Err(Error::OpeningLength {
                expected: 16,
                actual: 15
            })
        );

        let mut long = sample();
        long.opening.push(0);
        assert_eq!(
            commit(SUITE, &long),
            Err(Error::OpeningLength {
                expected: 16,
                actual: 17
            })
        );
    }

    #[test]
    fn commitment_from_slice_checks_length() {
        assert!(Commitment::from_slice(&[0_u8; 32]).is_ok());
        assert_eq!(
            Commitment::from_slice(&[0_u8; 31]),
            Err(Error::CommitmentLength {
                expected: 32,
                actual: 31
            })
        );
    }

    /// Both suites share `Kc` and SHA-256, so a commitment is suite-independent
    /// today. Pinned as a test because it is a property of the registry, not of
    /// the protocol: if a suite with a different hash is ever added, this is the
    /// assertion that should start failing.
    #[test]
    fn both_registered_suites_agree() {
        let value = sample();
        let p256 = commit(CipherSuite::Kt128Sha256P256, &value).unwrap();
        let ed25519 = commit(CipherSuite::Kt128Sha256Ed25519, &value).unwrap();
        assert_eq!(p256.as_bytes(), ed25519.as_bytes());
    }
}
