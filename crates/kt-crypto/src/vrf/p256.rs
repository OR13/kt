//! `ECVRF-P256-SHA256-TAI` (RFC 9381 §5.5), which §17.1 selects for
//! `KT_128_SHA256_P256`.
//!
//! Verification only. A VRF proof is produced by the log and consumed by everyone
//! else, so proving is a log's operation; [`super::edwards25519`] implements it
//! because its test vectors are round-trippable against RFC 9381 without a nonce
//! generator, and P-256's are not — RFC 9381 §5.4.2.1 derives the nonce with
//! RFC 6979, which is a signing concern this implementation has no use for. What a
//! client has to be able to do — take an 81-byte proof from a `BinaryLadderStep`
//! and recover the search key it commits to — is here in full.
//!
//! # Differences from edwards25519, all of them load-bearing
//!
//! | | edwards25519 | P-256 |
//! |---|---|---|
//! | hash | SHA-512 | SHA-256 |
//! | `suite_string` | `0x03` | `0x01` |
//! | integers | little-endian | **big-endian** |
//! | encoded point | 32 bytes | 33 bytes, SEC1 compressed |
//! | `VRF.Np` | 80 | **81** |
//! | `beta_string` | 64 bytes, truncated to 32 | 32 bytes, used whole |
//! | cofactor | 8, cleared explicitly | 1, nothing to clear |
//!
//! The byte order is the one to watch. RFC 9381's `string_to_int` follows the
//! curve's own convention, which for the NIST curves is big-endian — the opposite
//! of the edwards25519 ciphersuites. A `c` or `s` read the other way round produces
//! a verifier that agrees with nothing.
//!
//! # Oracles
//!
//! Two, and they are independent of each other: RFC 9381's Appendix B.1 test
//! vectors for `ECVRF-P256-SHA256-TAI`, which are in the tests below and settle the
//! byte order and every domain separator, and the peer's `crypto/vrf/p256` by way
//! of `interop/vectors/vrf.json`.

use p256::elliptic_curve::PrimeField as _;
use p256::elliptic_curve::sec1::{FromSec1Point as _, Sec1Point, ToSec1Point as _};
use p256::elliptic_curve::subtle::ConstantTimeEq as _;
use p256::{AffinePoint, ProjectivePoint, Scalar};
use sha2::{Digest as _, Sha256};

use kt_wire::codec::Encode as _;
use kt_wire::structs::{HashValue, VrfInput};

use super::{Error, Output, Result};

/// `suite_string` for `ECVRF-P256-SHA256-TAI` (RFC 9381 §5.5).
const SUITE_STRING: u8 = 0x01;

/// Domain separators (RFC 9381 §5.4.1.1, §5.4.3, §5.4.4).
const ENCODE_TO_CURVE_FRONT: u8 = 0x01;
const CHALLENGE_FRONT: u8 = 0x02;
const PROOF_TO_HASH_FRONT: u8 = 0x03;
const SEPARATOR_BACK: u8 = 0x00;

/// `cLen`: the challenge's length in bytes (RFC 9381 §5.5).
const C_LEN: usize = 16;
/// `qLen`: the scalar `s`'s length in bytes.
const Q_LEN: usize = 32;
/// `ptLen`: a SEC1 compressed point's length in bytes.
const PT_LEN: usize = 33;

/// `VRF.Np` for `KT_128_SHA256_P256`: the proof size in bytes (§17.1).
pub const PROOF_SIZE: usize = PT_LEN + C_LEN + Q_LEN;

/// A public key's length in bytes: SEC1 compressed.
pub const PUBLIC_KEY_SIZE: usize = PT_LEN;

/// A VRF proof: `VRF.Np` bytes of `Gamma || c || s` (RFC 9381 §5.4.4).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Proof([u8; PROOF_SIZE]);

impl Proof {
    /// Wraps `VRF.Np` bytes from the wire.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PROOF_SIZE]) -> Self {
        Self(bytes)
    }

    /// Wraps a slice that must be exactly `VRF.Np` bytes.
    ///
    /// # Errors
    ///
    /// [`Error::ProofLength`] if it is not.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let array = <[u8; PROOF_SIZE]>::try_from(bytes).map_err(|_| Error::ProofLength {
            expected: PROOF_SIZE,
            actual: bytes.len(),
        })?;
        Ok(Self(array))
    }

    /// The proof bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PROOF_SIZE] {
        &self.0
    }

    /// Splits the proof into `(Gamma, c, s)` (RFC 9381 §5.4.4 `ECVRF_decode_proof`).
    ///
    /// `c` is `cLen` bytes and `s` is `qLen`, both big-endian, and both are widened
    /// to a full scalar here. Step 7 requires rejecting `s >= q`, which
    /// [`Scalar::from_repr`] does by construction.
    fn decode(&self) -> Result<(ProjectivePoint, Scalar, Scalar)> {
        let gamma_bytes = self.0.get(..PT_LEN).ok_or(Error::MalformedGamma)?;
        let gamma = decode_point(gamma_bytes).ok_or(Error::MalformedGamma)?;

        // `c` occupies the *low* `cLen` bytes of a big-endian scalar, so it is
        // left-padded rather than right-padded. Getting this backwards multiplies by
        // 2^128 times the intended value.
        let mut c_wide = [0_u8; Q_LEN];
        let c_slice = self
            .0
            .get(PT_LEN..PT_LEN.saturating_add(C_LEN))
            .ok_or(Error::BadProof)?;
        c_wide
            .get_mut(Q_LEN.saturating_sub(C_LEN)..)
            .ok_or(Error::BadProof)?
            .copy_from_slice(c_slice);
        // A `cLen`-byte value is far below the group order, so this cannot fail.
        let c = Option::<Scalar>::from(Scalar::from_repr(c_wide.into())).ok_or(Error::BadProof)?;

        let s_slice = self
            .0
            .get(PT_LEN.saturating_add(C_LEN)..)
            .ok_or(Error::BadProof)?;
        let s_bytes = <[u8; Q_LEN]>::try_from(s_slice).map_err(|_| Error::BadProof)?;
        let s = Option::<Scalar>::from(Scalar::from_repr(s_bytes.into()))
            .ok_or(Error::NonCanonicalScalar)?;

        Ok((gamma, c, s))
    }

    /// `Gamma`'s SEC1 compressed encoding, which is what `proof_to_hash` hashes.
    fn gamma_bytes(&self) -> Result<&[u8]> {
        self.0.get(..PT_LEN).ok_or(Error::MalformedGamma)
    }
}

/// A VRF public key: a SEC1 compressed P-256 point.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    point: ProjectivePoint,
    /// The compressed encoding, kept because `encode_to_curve`'s salt is exactly
    /// these bytes and recomputing it per counter attempt would be wasteful.
    encoded: [u8; PUBLIC_KEY_SIZE],
}

impl PublicKey {
    /// Parses a SEC1 point.
    ///
    /// Both the compressed (33-byte) and uncompressed (65-byte) encodings are
    /// accepted, because §11.2 carries the key as `opaque vrf_public_key<0..2^16-1>`
    /// and says nothing about which. The peer emits compressed and accepts either.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedPublicKey`] if the bytes are not a point on the curve, or
    /// are the point at infinity — which RFC 9381 §5.4.5 requires rejecting, and
    /// which for a prime-order curve is the only key that commits to nothing.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let point = decode_point(bytes).ok_or(Error::MalformedPublicKey)?;
        if bool::from(point.to_affine().is_identity()) {
            return Err(Error::SmallOrderPublicKey);
        }
        let encoded = compress(&point);
        Ok(Self { point, encoded })
    }

    /// The key's SEC1 compressed encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.encoded
    }

    /// Verifies a proof over an arbitrary `alpha` and returns the output (RFC 9381
    /// §5.3 `ECVRF_verify`, §5.2 `ECVRF_proof_to_hash`).
    ///
    /// # Errors
    ///
    /// [`Error::MalformedGamma`] or [`Error::NonCanonicalScalar`] if the proof does
    /// not decode, and [`Error::BadProof`] if the recomputed challenge differs.
    pub fn verify_raw(&self, alpha: &[u8], proof: &Proof) -> Result<Output> {
        verify_steps(self, alpha, proof)
    }

    /// Verifies a proof over a `VrfInput` and returns the search key (§11.7).
    ///
    /// # Errors
    ///
    /// [`Error::Wire`] if the input cannot be encoded, plus anything
    /// [`PublicKey::verify_raw`] reports.
    pub fn verify(&self, input: &VrfInput, proof: &Proof) -> Result<Output> {
        let mut encoder = kt_wire::codec::Encoder::new();
        input.encode(&mut encoder)?;
        self.verify_raw(encoder.as_bytes(), proof)
    }
}

/// RFC 9381 §5.4.1.1 `ECVRF_encode_to_curve_try_and_increment`.
///
/// Hashes `salt || alpha || ctr` and reads the digest as the *x* coordinate of a
/// compressed point with an even *y*, incrementing `ctr` until one lands on the
/// curve. Two attempts in three succeed, so the loop is short; it is bounded at 256
/// by the counter being a single byte, and returning [`None`] there rather than
/// panicking is the difference between a malformed input and a crash.
fn encode_to_curve(salt: &[u8; PUBLIC_KEY_SIZE], alpha: &[u8]) -> Option<ProjectivePoint> {
    for ctr in 0..=u8::MAX {
        let mut hasher = Sha256::new();
        hasher.update([SUITE_STRING, ENCODE_TO_CURVE_FRONT]);
        hasher.update(salt);
        hasher.update(alpha);
        hasher.update([ctr, SEPARATOR_BACK]);
        let hashed = hasher.finalize();

        let mut candidate = [0_u8; PT_LEN];
        // SEC1 tag 0x02: compressed, even y. RFC 9381 §5.5 fixes it for this suite,
        // so a digest that is a valid x coordinate yields exactly one point.
        *candidate.first_mut()? = 0x02;
        candidate.get_mut(1..)?.copy_from_slice(&hashed);

        if let Some(point) = decode_point(&candidate) {
            // P-256 has cofactor 1, so there is no small-order component to clear —
            // the step edwards25519 needs `mul_by_cofactor` for. The identity cannot
            // arise here either: a compressed encoding with a tag byte always names
            // an affine point.
            return Some(point);
        }
    }
    None
}

/// RFC 9381 §5.4.3 `ECVRF_challenge_generation`, truncated to `cLen` bytes.
fn challenge(points: [&ProjectivePoint; 5]) -> [u8; C_LEN] {
    let mut hasher = Sha256::new();
    hasher.update([SUITE_STRING, CHALLENGE_FRONT]);
    for point in points {
        hasher.update(compress(point));
    }
    hasher.update([SEPARATOR_BACK]);
    let hashed = hasher.finalize();

    let mut out = [0_u8; C_LEN];
    // The digest is 32 bytes and `C_LEN` is 16, so the slice always exists.
    if let Some(front) = hashed.get(..C_LEN) {
        out.copy_from_slice(front);
    }
    out
}

/// RFC 9381 §5.2 `ECVRF_proof_to_hash`.
///
/// No truncation and no cofactor multiplication: `beta_string` is already 32 bytes,
/// which is `VRF.Nh`, and P-256's cofactor is 1.
fn proof_to_hash(gamma_bytes: &[u8]) -> Output {
    let mut hasher = Sha256::new();
    hasher.update([SUITE_STRING, PROOF_TO_HASH_FRONT]);
    hasher.update(gamma_bytes);
    hasher.update([SEPARATOR_BACK]);
    let hashed = hasher.finalize();

    let mut out = [0_u8; 32];
    out.copy_from_slice(&hashed);
    Output::from_hash(HashValue::from_bytes(out))
}

/// Decodes a SEC1 point, rejecting anything not on the curve.
fn decode_point(bytes: &[u8]) -> Option<ProjectivePoint> {
    let encoded = Sec1Point::<p256::NistP256>::from_bytes(bytes).ok()?;
    let affine = Option::<AffinePoint>::from(AffinePoint::from_sec1_point(&encoded))?;
    Some(ProjectivePoint::from(affine))
}

/// A point's SEC1 compressed encoding.
fn compress(point: &ProjectivePoint) -> [u8; PT_LEN] {
    let mut out = [0_u8; PT_LEN];
    let bytes = point.to_affine().to_sec1_point(true);
    if let Some(slot) = out.get_mut(..bytes.as_bytes().len()) {
        slot.copy_from_slice(bytes.as_bytes());
    }
    out
}

/// Everything a verifier needs from a decoded proof, in one place so that
/// [`PublicKey::verify_raw`] reads like RFC 9381 §5.3's numbered steps.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "these are elliptic-curve group operations on p256 types, not machine integers:               scalar multiplication and point addition are total on the group and cannot               overflow or panic. The lint reads the operator overloads as arithmetic it should               be guarding."
)]
fn verify_steps(key: &PublicKey, alpha: &[u8], proof: &Proof) -> Result<Output> {
    // Steps 1-3: decode the proof. `c` comes back as a scalar for the arithmetic and
    // is compared in its wire form below, because RFC 9381 step 8 compares the
    // *strings*, and a scalar comparison would accept a `c` that is congruent but
    // differently encoded.
    let (gamma, c, s) = proof.decode()?;

    // Step 4: H = encode_to_curve(PK, alpha).
    let h = encode_to_curve(key.as_bytes(), alpha).ok_or(Error::BadProof)?;

    // Step 5: U = s*B - c*Y.
    let u = (ProjectivePoint::GENERATOR * s) - (key.point * c);
    // Step 6: V = s*H - c*Gamma.
    let v = (h * s) - (gamma * c);

    // Steps 7-8: c' = challenge(Y, H, Gamma, U, V), and c' must equal c.
    let recomputed = challenge([&key.point, &h, &gamma, &u, &v]);
    let mut supplied = [0_u8; C_LEN];
    supplied.copy_from_slice(
        proof
            .0
            .get(PT_LEN..PT_LEN.saturating_add(C_LEN))
            .ok_or(Error::BadProof)?,
    );
    // Constant-time, matching the edwards25519 path: a challenge comparison that
    // leaks where two proofs first differ is a timing oracle on the log's key.
    if !bool::from(recomputed.ct_eq(&supplied)) {
        return Err(Error::BadProof);
    }

    Ok(proof_to_hash(proof.gamma_bytes()?))
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests fail loudly by panicking; the lints protect the verification paths"
)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// RFC 9381 Appendix B.1's `ECVRF-P256-SHA256-TAI` examples, as `(public key, alpha,
    /// beta, pi)`. These are the oracle that matters: they are independent of both this
    /// implementation and the peer, and they settle every choice this module makes — the
    /// suite string, the three domain separators, the big-endian integers, the SEC1 `0x02`
    /// tag in `encode_to_curve`, and the absence of truncation in `proof_to_hash`. Getting
    /// any one of them wrong fails all three.
    const VECTORS: [(&str, &str, &str, &str); 3] = [
        (
            "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
            "73616d706c65",
            "a3ad7b0ef73d8fc6655053ea22f9bede8c743f08bbed3d38821f0e16474b505e",
            "035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4a53f0a46f018bc2c\
             56e58d383f2305e0975972c26feea0eb122fe7893c15af376b33edf7de17c6ea056d4d82de6bc02f",
        ),
        (
            "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
            "74657374",
            "a284f94ceec2ff4b3794629da7cbafa49121972671b466cab4ce170aa365f26d",
            "034dac60aba508ba0c01aa9be80377ebd7562c4a52d74722e0abae7dc3080ddb56c19e067b15a8a817\
             4905b13617804534214f935b94c2287f797e393eb0816969d864f37625b443f30f1a5a33f2b3c854",
        ),
        (
            "03596375e6ce57e0f20294fc46bdfcfd19a39f8161b58695b3ec5b3d16427c274d",
            "4578616d706c65207573696e67204543445341206b65792066726f6d20417070656e646978204c2e34\
             2e32206f6620414e53492e58392d36322d32303035",
            "90871e06da5caa39a3c61578ebb844de8635e27ac0b13e829997d0d95dd98c19",
            "03d03398bf53aa23831d7d1b2937e005fb0062cbefa06796579f2a1fc7e7b8c667d091c00b0f5c3619\
             d10ecea44363b5a599cadc5b2957e223fec62e81f7b4825fc799a771a3d7334b9186bdbee87316b1",
        ),
    ];

    fn unhex(text: &str) -> Vec<u8> {
        let cleaned: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        cleaned
            .chunks(2)
            .map(|pair| {
                let digit = |b: u8| match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    _ => panic!("not hex: {b}"),
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }

    #[test]
    fn rfc_9381_vectors_verify() {
        for (index, (public, alpha, beta, pi)) in VECTORS.iter().enumerate() {
            let key = PublicKey::from_slice(&unhex(public)).unwrap();
            let proof = Proof::from_slice(&unhex(pi)).unwrap();
            let output = key.verify_raw(&unhex(alpha), &proof).unwrap();
            assert_eq!(
                output.as_bytes().as_slice(),
                unhex(beta).as_slice(),
                "vector {index}"
            );
            // A compressed key round-trips to the bytes it came from.
            assert_eq!(key.as_bytes().as_slice(), unhex(public).as_slice());
        }
    }

    /// The proof is bound to the message. RFC 9381's own vectors share a key across two
    /// different `alpha`s, so each one's proof must fail against the other's message —
    /// which is a sharper check than a random tamper, because both proofs are individually
    /// valid.
    #[test]
    fn a_proof_does_not_verify_for_another_message() {
        let key = PublicKey::from_slice(&unhex(VECTORS[0].0)).unwrap();
        let first = Proof::from_slice(&unhex(VECTORS[0].3)).unwrap();
        let second = Proof::from_slice(&unhex(VECTORS[1].3)).unwrap();
        assert_eq!(
            key.verify_raw(&unhex(VECTORS[1].1), &first),
            Err(Error::BadProof)
        );
        assert_eq!(
            key.verify_raw(&unhex(VECTORS[0].1), &second),
            Err(Error::BadProof)
        );
    }

    /// And to the key. Vector 2 uses a different key from vectors 0 and 1, so crossing them
    /// must fail — the check that `encode_to_curve`'s salt really is the public key.
    #[test]
    fn a_proof_does_not_verify_under_another_key() {
        let other = PublicKey::from_slice(&unhex(VECTORS[2].0)).unwrap();
        let proof = Proof::from_slice(&unhex(VECTORS[0].3)).unwrap();
        assert_eq!(
            other.verify_raw(&unhex(VECTORS[0].1), &proof),
            Err(Error::BadProof)
        );
    }

    /// Every single-byte mutation of a valid proof must be rejected. This is where the
    /// `Gamma`/`c`/`s` boundaries get checked without having to reason about them: a flipped
    /// bit in `Gamma` usually leaves the curve, one in `c` or `s` changes the arithmetic, and
    /// all three must come back as an error rather than a different output.
    #[test]
    fn every_single_byte_mutation_is_rejected() {
        let key = PublicKey::from_slice(&unhex(VECTORS[0].0)).unwrap();
        let bytes = unhex(VECTORS[0].3);
        let alpha = unhex(VECTORS[0].1);
        for position in 0..bytes.len() {
            let mut mutated = bytes.clone();
            mutated[position] ^= 0x01;
            let proof = Proof::from_slice(&mutated).unwrap();
            assert!(
                key.verify_raw(&alpha, &proof).is_err(),
                "byte {position} flipped and the proof still verified"
            );
        }
    }

    /// The length is `VRF.Np`, and nothing else. §13.1's `BinaryLadderStep` reads a proof as
    /// a fixed-size field, so a length mismatch means the response was decoded under the
    /// wrong cipher suite — 80 bytes is an edwards25519 proof.
    #[test]
    fn the_proof_length_is_np() {
        assert_eq!(PROOF_SIZE, 81);
        let short = unhex(VECTORS[0].3)[..80].to_vec();
        assert_eq!(
            Proof::from_slice(&short),
            Err(Error::ProofLength {
                expected: 81,
                actual: 80
            })
        );
    }

    /// A public key must be a point on the curve, and must not be the identity. On a
    /// prime-order curve the identity is the only element that commits to nothing, and SEC1
    /// spells it as a single zero byte.
    #[test]
    fn malformed_public_keys_are_refused() {
        // Right length and tag, wrong x coordinate: not on the curve.
        let mut bogus = unhex(VECTORS[0].0);
        bogus[1] ^= 0xff;
        assert_eq!(
            PublicKey::from_slice(&bogus),
            Err(Error::MalformedPublicKey)
        );
        // SEC1's identity encoding is a single zero byte, and it *parses* — so it is caught
        // by the explicit RFC 9381 §5.4.5 check rather than by point decoding, and reports
        // the more specific error.
        assert_eq!(
            PublicKey::from_slice(&[0x00]),
            Err(Error::SmallOrderPublicKey)
        );
        assert_eq!(PublicKey::from_slice(&[]), Err(Error::MalformedPublicKey));
        // An edwards25519 key is 32 bytes, which is not a SEC1 encoding at all.
        assert_eq!(
            PublicKey::from_slice(&[0x11; 32]),
            Err(Error::MalformedPublicKey)
        );
    }

    /// `s >= q` is rejected outright (RFC 9381 §5.4.4 step 7), rather than reduced. Accepting
    /// it would make proofs malleable: `s` and `s + q` would both verify.
    #[test]
    fn a_non_canonical_s_is_refused() {
        let mut bytes = unhex(VECTORS[0].3);
        // The group order itself, which is the smallest non-canonical value.
        let order = unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        bytes[49..].copy_from_slice(&order);
        let proof = Proof::from_slice(&bytes).unwrap();
        let key = PublicKey::from_slice(&unhex(VECTORS[0].0)).unwrap();
        assert_eq!(
            key.verify_raw(&unhex(VECTORS[0].1), &proof),
            Err(Error::NonCanonicalScalar)
        );
    }

    /// The §11.7 entry point: a `VrfInput` rather than raw bytes. The search key is the
    /// output, so this is the shape a prefix tree lookup actually uses.
    #[test]
    fn a_vrf_input_produces_a_search_key() {
        let key = PublicKey::from_slice(&unhex(VECTORS[0].0)).unwrap();
        let proof = Proof::from_slice(&unhex(VECTORS[0].3)).unwrap();
        let input = VrfInput::new(b"alice@example.com".to_vec(), 3);
        // The vectors' alpha is not a VrfInput encoding, so this must fail rather than
        // silently accept — the point is that `verify` encodes the input rather than
        // taking bytes.
        assert_eq!(key.verify(&input, &proof), Err(Error::BadProof));
    }
}
