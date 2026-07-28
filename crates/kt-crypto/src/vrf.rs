//! Verifiable Random Function (`draft-ietf-keytrans-protocol-05` §11.7).
//!
//! Each label-version pair's search key in the prefix tree is the VRF output over
//! a [`VrfInput`] (§11.7). That is what keeps labels private: the tree is indexed
//! by a value only the log can compute, so a user who is handed a search key
//! learns nothing about the label behind it, and — because the VRF is *verifiable*
//! — the log cannot use a different key for the same label than the one it
//! proves.
//!
//! # What this implements
//!
//! `ECVRF-EDWARDS25519-SHA512-TAI` from [RFC 9381], which §17.1 selects for
//! `KT_128_SHA256_Ed25519`, **with the output truncated to 32 bytes** as §17.1
//! requires. The `KT_128_SHA256_P256` suite's `ECVRF-P256-SHA256-TAI` is not
//! implemented yet; [`Error::UnsupportedSuite`] says so rather than quietly using
//! the wrong curve.
//!
//! Note the two hash functions in play. The cipher suite's hash is SHA-256 and is
//! what [`crate::hash`] provides; the VRF's hash is **SHA-512**, fixed by the
//! ECVRF ciphersuite, and is used only inside this module. They are not the same
//! parameter and conflating them produces a VRF that verifies against itself and
//! nothing else.
//!
//! # Byte-order trap
//!
//! For the edwards25519 ciphersuites, RFC 9381's `int_to_string` and
//! `string_to_int` are **little-endian**, following RFC 8032 — unlike the
//! big-endian integers everywhere else in the KT wire format. `c` and `s` in a
//! proof are little-endian, and so is the challenge read out of a hash. The RFC's
//! own test vectors are what adjudicate this, and they are in the tests below.
//!
//! # Oracles
//!
//! Three, in increasing distance from this code: RFC 9381's Appendix B vectors
//! (implementation-independent, and the ones that matter most), the peer's
//! `crypto/vrf/edwards25519`, and `interop/vectors/vrf.json`.
//!
//! [RFC 9381]: https://www.rfc-editor.org/rfc/rfc9381.html

use alloc::vec::Vec;
use core::fmt;

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity as _;
use sha2::{Digest as _, Sha512};

use kt_wire::codec::{self, Encode as _};
use kt_wire::structs::{HashValue, VrfInput};

use crate::suite::CipherSuite;

/// `suite_string` for `ECVRF-EDWARDS25519-SHA512-TAI` (RFC 9381 §5.5).
const SUITE_STRING: u8 = 0x03;

/// Domain separators (RFC 9381 §5.4.1.1, §5.4.3, §5.4.4).
const ENCODE_TO_CURVE_FRONT: u8 = 0x01;
const CHALLENGE_FRONT: u8 = 0x02;
const PROOF_TO_HASH_FRONT: u8 = 0x03;
const SEPARATOR_BACK: u8 = 0x00;

/// `cLen`: the challenge's length in bytes (RFC 9381 §5.5).
const C_LEN: usize = 16;
/// `qLen`: the scalar `s`'s length in bytes.
const Q_LEN: usize = 32;
/// `ptLen`: an encoded point's length in bytes.
const PT_LEN: usize = 32;

/// `VRF.Np` for `KT_128_SHA256_Ed25519`: the proof size in bytes (§17.1).
pub const PROOF_SIZE: usize = PT_LEN + C_LEN + Q_LEN;

/// `VRF.Nh` for both registered suites: the output length in bytes (§17.1).
///
/// RFC 9381's `beta_string` for this ciphersuite is 64 bytes; §17.1 specifies
/// "with the output truncated to 32 bytes", so that is what a search key is.
pub const OUTPUT_SIZE: usize = 32;

/// A secret key's length in bytes (RFC 8032 §5.1.5).
pub const SECRET_KEY_SIZE: usize = 32;

/// A public key's length in bytes.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Something wrong with a VRF key, proof, or the suite asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The cipher suite's VRF is not implemented here.
    UnsupportedSuite {
        /// The suite that was asked for.
        suite: CipherSuite,
    },
    /// A public key was not a valid compressed Edwards point.
    MalformedPublicKey,
    /// A public key was of small order, so it commits to nothing.
    ///
    /// RFC 9381 §5.4.5 `ECVRF_validate_key`. Checked here because in this protocol
    /// the VRF public key arrives in a `Configuration` from the log, and a
    /// small-order key would let it produce the same output for every label.
    SmallOrderPublicKey,
    /// A proof was not `VRF.Np` bytes.
    ProofLength {
        /// `VRF.Np`.
        expected: usize,
        /// What was supplied.
        actual: usize,
    },
    /// A proof's `Gamma` was not a valid compressed Edwards point.
    MalformedGamma,
    /// A proof's `s` was not a canonical scalar, i.e. `s >= q`.
    ///
    /// RFC 9381 §5.4.4 step 7 requires rejecting these. Accepting them would make
    /// proofs malleable: several byte strings would verify for one signature.
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

    /// Splits the proof into `(Gamma, c, s)` (RFC 9381 §5.4.4
    /// `ECVRF_decode_proof`).
    fn decode(&self) -> Result<(EdwardsPoint, Scalar, Scalar)> {
        let gamma_bytes: [u8; PT_LEN] = self
            .0
            .get(..PT_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::MalformedGamma)?;
        let gamma = CompressedEdwardsY(gamma_bytes)
            .decompress()
            .ok_or(Error::MalformedGamma)?;

        // `c` is cLen bytes, little-endian for the edwards25519 ciphersuites, and
        // is always below 2^128 so it is canonical by construction.
        let mut c_bytes = [0_u8; 32];
        let c_slice = self
            .0
            .get(PT_LEN..PT_LEN.saturating_add(C_LEN))
            .ok_or(Error::BadProof)?;
        c_bytes
            .get_mut(..C_LEN)
            .ok_or(Error::BadProof)?
            .copy_from_slice(c_slice);
        let c = Scalar::from_bytes_mod_order(c_bytes);

        // `s` must be canonical: RFC 9381 §5.4.4 rejects s >= q.
        let s_bytes: [u8; Q_LEN] = self
            .0
            .get(PT_LEN.saturating_add(C_LEN)..)
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::BadProof)?;
        let s =
            Option::from(Scalar::from_canonical_bytes(s_bytes)).ok_or(Error::NonCanonicalScalar)?;

        Ok((gamma, c, s))
    }
}

/// A VRF secret key: the 32-byte seed of RFC 8032 §5.1.5.
///
/// Held by the Transparency Log only. Present here so tests and the interop
/// harness can produce proofs; a client never has one.
#[derive(Clone)]
pub struct SecretKey {
    seed: [u8; SECRET_KEY_SIZE],
    /// The secret scalar `x`, derived per RFC 8032 §5.1.5.
    scalar: Scalar,
    /// The upper half of `Hash(SK)`, which the nonce derivation needs.
    nonce_seed: [u8; 32],
    public: PublicKey,
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key material, not even truncated.
        f.debug_struct("SecretKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl SecretKey {
    /// Derives a key from a 32-byte seed (RFC 8032 §5.1.5).
    #[must_use]
    pub fn from_seed(seed: [u8; SECRET_KEY_SIZE]) -> Self {
        let hashed = Sha512::digest(seed);

        // The lower half, clamped: clear the low three bits of the first byte and
        // the top bit of the last, then set the second-highest.
        let mut lower = [0_u8; 32];
        lower.copy_from_slice(hashed.get(..32).unwrap_or(&[0; 32]));
        if let Some(first) = lower.first_mut() {
            *first &= 0b1111_1000;
        }
        if let Some(last) = lower.last_mut() {
            *last &= 0b0111_1111;
            *last |= 0b0100_0000;
        }
        let scalar = Scalar::from_bytes_mod_order(lower);

        let mut nonce_seed = [0_u8; 32];
        nonce_seed.copy_from_slice(hashed.get(32..64).unwrap_or(&[0; 32]));

        let point = EdwardsPoint::mul_base(&scalar);
        let public = PublicKey {
            encoded: point.compress().to_bytes(),
            point,
        };

        Self {
            seed,
            scalar,
            nonce_seed,
            public,
        }
    }

    /// The matching public key.
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The seed, for writing a key into a test vector.
    #[must_use]
    pub const fn seed(&self) -> &[u8; SECRET_KEY_SIZE] {
        &self.seed
    }

    /// Proves the VRF over a raw `alpha_string` (RFC 9381 §5.1 `ECVRF_prove`).
    ///
    /// Prefer [`SecretKey::evaluate`], which takes the §11.7 [`VrfInput`]; this is
    /// exposed so the RFC's own test vectors, whose inputs are raw byte strings,
    /// can be run against it.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedSuite`] for a suite whose VRF is not implemented.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "these are elliptic-curve group operations on curve25519-dalek types, \
                  not machine integers: scalar multiplication and point addition are \
                  total on the group and cannot overflow or panic. The lint reads the \
                  operator overloads as arithmetic it should be guarding."
    )]
    pub fn prove_raw(&self, suite: CipherSuite, alpha: &[u8]) -> Result<(Output, Proof)> {
        check_suite(suite)?;

        // 2. H = encode_to_curve(PK_string, alpha)
        let h = encode_to_curve(&self.public.encoded, alpha);
        let h_string = h.compress().to_bytes();

        // 4. Gamma = x*H
        let gamma = h * self.scalar;

        // 5. k = nonce_generation(SK, h_string)
        let k = nonce(&self.nonce_seed, &h_string);

        // 6. c = challenge_generation(Y, H, Gamma, k*B, k*H)
        let c = challenge(&[
            self.public.point,
            h,
            gamma,
            EdwardsPoint::mul_base(&k),
            h * k,
        ]);

        // 7. s = (k + c*x) mod q
        let s = k + c * self.scalar;

        let mut proof = [0_u8; PROOF_SIZE];
        write_proof(&mut proof, &gamma, &c, &s);
        Ok((proof_to_hash(&gamma), Proof(proof)))
    }

    /// Proves the VRF over a §11.7 [`VrfInput`], giving the label-version pair's
    /// search key.
    ///
    /// # Errors
    ///
    /// [`Error::Wire`] if `input` cannot be encoded, or
    /// [`Error::UnsupportedSuite`].
    pub fn evaluate(&self, suite: CipherSuite, input: &VrfInput) -> Result<(Output, Proof)> {
        self.prove_raw(suite, &encode_input(input)?)
    }
}

/// A VRF public key: `Configuration.vrf_public_key` (§11.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    point: EdwardsPoint,
    encoded: [u8; PUBLIC_KEY_SIZE],
}

impl PublicKey {
    /// Decodes and validates a public key.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedPublicKey`] if it is not a valid compressed point, or
    /// [`Error::SmallOrderPublicKey`] if it is of small order (RFC 9381 §5.4.5).
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_SIZE]) -> Result<Self> {
        let point = CompressedEdwardsY(bytes)
            .decompress()
            .ok_or(Error::MalformedPublicKey)?;
        // Covers the identity too: order 1 divides the cofactor.
        if point.is_small_order() {
            return Err(Error::SmallOrderPublicKey);
        }
        Ok(Self {
            point,
            encoded: bytes,
        })
    }

    /// Decodes a public key from a slice.
    ///
    /// # Errors
    ///
    /// As [`PublicKey::from_bytes`], plus [`Error::MalformedPublicKey`] if the
    /// slice is the wrong length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let array =
            <[u8; PUBLIC_KEY_SIZE]>::try_from(bytes).map_err(|_| Error::MalformedPublicKey)?;
        Self::from_bytes(array)
    }

    /// The encoded key.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.encoded
    }

    /// Verifies a proof over a raw `alpha_string` and returns the output it
    /// justifies (RFC 9381 §5.3 `ECVRF_verify`).
    ///
    /// # Errors
    ///
    /// [`Error::BadProof`] if the challenge does not recompute, plus the decoding
    /// errors of [`Proof`].
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "these are elliptic-curve group operations on curve25519-dalek types, \
                  not machine integers: scalar multiplication and point addition are \
                  total on the group and cannot overflow or panic. The lint reads the \
                  operator overloads as arithmetic it should be guarding."
    )]
    pub fn verify_raw(&self, suite: CipherSuite, alpha: &[u8], proof: &Proof) -> Result<Output> {
        check_suite(suite)?;
        let (gamma, c, s) = proof.decode()?;

        // 7. H = encode_to_curve(PK_string, alpha)
        let h = encode_to_curve(&self.encoded, alpha);
        // 8. U = s*B - c*Y      9. V = s*H - c*Gamma
        let u = EdwardsPoint::mul_base(&s) - self.point * c;
        let v = h * s - gamma * c;
        // 10. c' = challenge_generation(Y, H, Gamma, U, V)
        let c_prime = challenge(&[self.point, h, gamma, u, v]);

        // 11. Constant-time comparison; `c` is public but there is no reason to
        // leak where two challenges first differ.
        if c == c_prime {
            Ok(proof_to_hash(&gamma))
        } else {
            Err(Error::BadProof)
        }
    }

    /// Verifies a proof over a §11.7 [`VrfInput`] and returns the search key.
    ///
    /// This is the client-facing operation: given the log's VRF public key, a
    /// label, a version, and a proof, it yields the prefix-tree search key that
    /// the rest of the verification is entitled to use — and nothing otherwise.
    ///
    /// # Errors
    ///
    /// As [`PublicKey::verify_raw`], plus [`Error::Wire`].
    pub fn verify(&self, suite: CipherSuite, input: &VrfInput, proof: &Proof) -> Result<Output> {
        self.verify_raw(suite, &encode_input(input)?, proof)
    }
}

/// Only the Ed25519 suite's VRF is implemented so far.
const fn check_suite(suite: CipherSuite) -> Result<()> {
    match suite {
        CipherSuite::Kt128Sha256Ed25519 => Ok(()),
        // ECVRF-P256-SHA256-TAI, VRF.Np = 81. Not implemented; saying so is better
        // than evaluating the wrong curve's VRF and producing a plausible search
        // key that nothing else agrees with.
        CipherSuite::Kt128Sha256P256 => Err(Error::UnsupportedSuite { suite }),
    }
}

fn encode_input(input: &VrfInput) -> Result<Vec<u8>> {
    let mut enc = codec::Encoder::new();
    input.encode(&mut enc)?;
    Ok(enc.into_bytes())
}

/// RFC 9381 §5.4.1.1 `ECVRF_encode_to_curve_try_and_increment`.
///
/// Hashes with an incrementing counter until the first 32 bytes decode as a point,
/// then multiplies by the cofactor. The loop is bounded at 256 because `ctr` is a
/// single octet (`int_to_string(ctr, 1)`); reaching the end would mean no counter
/// value works, which for a 32-byte hash has probability around `2^-256` per
/// attempt. The identity is returned in that case, which cannot verify against any
/// real proof.
fn encode_to_curve(salt: &[u8; PUBLIC_KEY_SIZE], alpha: &[u8]) -> EdwardsPoint {
    for ctr in 0..=u8::MAX {
        let mut hasher = Sha512::new();
        hasher.update([SUITE_STRING, ENCODE_TO_CURVE_FRONT]);
        hasher.update(salt);
        hasher.update(alpha);
        hasher.update([ctr, SEPARATOR_BACK]);
        let hashed = hasher.finalize();

        let Some(candidate) = hashed
            .get(..PT_LEN)
            .and_then(|s| <[u8; PT_LEN]>::try_from(s).ok())
        else {
            continue;
        };
        if let Some(point) = CompressedEdwardsY(candidate).decompress() {
            let cleared = point.mul_by_cofactor();
            if !cleared.is_identity() {
                return cleared;
            }
        }
    }
    EdwardsPoint::default()
}

/// RFC 9381 §5.4.2.2 `ECVRF_nonce_generation_RFC8032`.
fn nonce(nonce_seed: &[u8; 32], h_string: &[u8; PT_LEN]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(nonce_seed);
    hasher.update(h_string);
    let hashed = hasher.finalize();
    let mut wide = [0_u8; 64];
    wide.copy_from_slice(&hashed);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// RFC 9381 §5.4.3 `ECVRF_challenge_generation`.
///
/// The challenge is the first `cLen` bytes of the hash, read as a little-endian
/// integer — the edwards25519 convention, and the detail most likely to be got
/// wrong, since the rest of this protocol is big-endian.
fn challenge(points: &[EdwardsPoint; 5]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update([SUITE_STRING, CHALLENGE_FRONT]);
    for point in points {
        hasher.update(point.compress().to_bytes());
    }
    hasher.update([SEPARATOR_BACK]);
    let hashed = hasher.finalize();

    let mut c_bytes = [0_u8; 32];
    if let (Some(target), Some(source)) = (c_bytes.get_mut(..C_LEN), hashed.get(..C_LEN)) {
        target.copy_from_slice(source);
    }
    Scalar::from_bytes_mod_order(c_bytes)
}

/// RFC 9381 §5.2 `ECVRF_proof_to_hash`, truncated to `VRF.Nh` per §17.1.
fn proof_to_hash(gamma: &EdwardsPoint) -> Output {
    let mut hasher = Sha512::new();
    hasher.update([SUITE_STRING, PROOF_TO_HASH_FRONT]);
    hasher.update(gamma.mul_by_cofactor().compress().to_bytes());
    hasher.update([SEPARATOR_BACK]);
    let hashed = hasher.finalize();

    let mut out = [0_u8; OUTPUT_SIZE];
    if let Some(prefix) = hashed.get(..OUTPUT_SIZE) {
        out.copy_from_slice(prefix);
    }
    Output(HashValue::from_bytes(out))
}

/// `pi_string = point_to_string(Gamma) || int_to_string(c, cLen) || int_to_string(s, qLen)`.
fn write_proof(out: &mut [u8; PROOF_SIZE], gamma: &EdwardsPoint, c: &Scalar, s: &Scalar) {
    let gamma_bytes = gamma.compress().to_bytes();
    let c_bytes = c.to_bytes();
    let s_bytes = s.to_bytes();
    if let Some(slot) = out.get_mut(..PT_LEN) {
        slot.copy_from_slice(&gamma_bytes);
    }
    // Little-endian, so the low cLen bytes are the challenge; the rest of a
    // 16-byte challenge widened to a scalar are zero.
    if let (Some(slot), Some(source)) = (
        out.get_mut(PT_LEN..PT_LEN.saturating_add(C_LEN)),
        c_bytes.get(..C_LEN),
    ) {
        slot.copy_from_slice(source);
    }
    if let Some(slot) = out.get_mut(PT_LEN.saturating_add(C_LEN)..) {
        slot.copy_from_slice(&s_bytes);
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "tests fail loudly by panicking; the lints protect library paths"
)]
mod tests {
    use super::*;
    use alloc::vec;

    const SUITE: CipherSuite = CipherSuite::Kt128Sha256Ed25519;

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(bytes: &[u8]) -> alloc::string::String {
        bytes.iter().map(|b| alloc::format!("{b:02x}")).collect()
    }

    /// RFC 9381 Appendix B.3, the three ECVRF-EDWARDS25519-SHA512-TAI examples.
    ///
    /// These are the oracle that matters most: they are independent of every
    /// implementation, so passing them means this is ECVRF and not merely
    /// self-consistent. `beta` in the RFC is the full 64-byte output; §17.1
    /// truncates it to 32, so each expected value is compared against its first
    /// half.
    #[test]
    fn rfc9381_test_vectors() {
        let vectors = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
                "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
                "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
                "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f",
            ),
        ];

        for (sk_hex, pk_hex, alpha_hex, pi_hex, beta_hex) in vectors {
            let seed: [u8; 32] = unhex(sk_hex).try_into().unwrap();
            let secret = SecretKey::from_seed(seed);
            let alpha = unhex(alpha_hex);

            assert_eq!(
                to_hex(secret.public_key().as_bytes()),
                pk_hex,
                "public key for {sk_hex}"
            );

            let (output, proof) = secret.prove_raw(SUITE, &alpha).unwrap();
            assert_eq!(
                to_hex(proof.as_bytes()),
                pi_hex,
                "proof for alpha {alpha_hex:?}"
            );
            assert_eq!(
                to_hex(output.as_bytes()),
                beta_hex.get(..64).unwrap(),
                "output for alpha {alpha_hex:?} (truncated to VRF.Nh per §17.1)"
            );

            // And verification recovers the same output from the proof alone.
            let public = PublicKey::from_slice(&unhex(pk_hex)).unwrap();
            let verified = public.verify_raw(SUITE, &alpha, &proof).unwrap();
            assert_eq!(verified, output);
        }
    }

    /// The proof size §17.1 states for this suite.
    #[test]
    fn proof_is_np_bytes() {
        assert_eq!(PROOF_SIZE, 80, "VRF.Np for KT_128_SHA256_Ed25519");
        assert_eq!(OUTPUT_SIZE, 32, "VRF.Nh");
        let secret = SecretKey::from_seed([7; 32]);
        let (_, proof) = secret.prove_raw(SUITE, b"alpha").unwrap();
        assert_eq!(proof.as_bytes().len(), 80);
    }

    /// §11.7: the search key is the VRF output over the encoded `VrfInput`, and the
    /// length prefix on `label` is what stops two different pairs from colliding.
    #[test]
    fn vrf_input_is_bound_field_by_field() {
        let secret = SecretKey::from_seed([1; 32]);
        let public = *secret.public_key();

        let (output, proof) = secret
            .evaluate(SUITE, &VrfInput::new(b"alice".to_vec(), 1))
            .unwrap();
        assert_eq!(
            public
                .verify(SUITE, &VrfInput::new(b"alice".to_vec(), 1), &proof)
                .unwrap(),
            output
        );

        // A different version, or a different label, is a different search key.
        for other in [
            VrfInput::new(b"alice".to_vec(), 2),
            VrfInput::new(b"alicf".to_vec(), 1),
            VrfInput::new(b"alic".to_vec(), 1),
            VrfInput::new(Vec::new(), 1),
        ] {
            let (other_output, _) = secret.evaluate(SUITE, &other).unwrap();
            assert_ne!(other_output, output, "{other:?} collided with alice@1");
            assert_eq!(
                public.verify(SUITE, &other, &proof),
                Err(Error::BadProof),
                "a proof for alice@1 must not verify for {other:?}"
            );
        }
    }

    /// The classic length-extension confusion the length prefix prevents: without
    /// it, `("ab", …)` and `("a", …)` could produce the same encoded input.
    #[test]
    fn label_and_version_cannot_be_confused() {
        let secret = SecretKey::from_seed([2; 32]);
        // Version 0x62 is 'b'. If the label were not length-prefixed, "a" at
        // version 0x62000000 and "ab" at some version could encode alike.
        let (a, _) = secret
            .evaluate(SUITE, &VrfInput::new(b"a".to_vec(), 0x6200_0000))
            .unwrap();
        let (ab, _) = secret
            .evaluate(SUITE, &VrfInput::new(b"ab".to_vec(), 0))
            .unwrap();
        assert_ne!(a, ab);
    }

    #[test]
    fn tampered_proofs_do_not_verify() {
        let secret = SecretKey::from_seed([3; 32]);
        let public = *secret.public_key();
        let input = VrfInput::new(b"bob".to_vec(), 7);
        let (_, proof) = secret.evaluate(SUITE, &input).unwrap();

        // Every single-bit flip in the proof must be rejected, whether it lands in
        // Gamma, the challenge, or the scalar.
        for byte in 0..PROOF_SIZE {
            for bit in 0..8_u32 {
                let mut bytes = *proof.as_bytes();
                bytes[byte] ^= 1 << bit;
                let broken = Proof::from_bytes(bytes);
                if broken == proof {
                    continue;
                }
                assert!(
                    public.verify(SUITE, &input, &broken).is_err(),
                    "flipping bit {bit} of byte {byte} still verified"
                );
            }
        }
    }

    /// A proof made with a different key must not verify, and neither must a proof
    /// verified against a different key.
    #[test]
    fn proofs_are_bound_to_their_key() {
        let input = VrfInput::new(b"carol".to_vec(), 0);
        let first = SecretKey::from_seed([4; 32]);
        let second = SecretKey::from_seed([5; 32]);
        let (_, proof) = first.evaluate(SUITE, &input).unwrap();
        assert_eq!(
            second.public_key().verify(SUITE, &input, &proof),
            Err(Error::BadProof)
        );
    }

    /// RFC 9381 §5.4.4 step 7: `s >= q` must be rejected, or proofs are malleable.
    #[test]
    fn non_canonical_scalars_are_rejected() {
        let secret = SecretKey::from_seed([6; 32]);
        let public = *secret.public_key();
        let input = VrfInput::new(b"dave".to_vec(), 1);
        let (_, proof) = secret.evaluate(SUITE, &input).unwrap();

        let mut bytes = *proof.as_bytes();
        // All-ones is far above the group order.
        for slot in bytes.get_mut(PT_LEN + C_LEN..).unwrap() {
            *slot = 0xff;
        }
        assert_eq!(
            public.verify(SUITE, &input, &Proof::from_bytes(bytes)),
            Err(Error::NonCanonicalScalar)
        );
    }

    /// An encoding that is not a point at all.
    ///
    /// Found by scanning rather than written down, because the obvious guesses are
    /// wrong: `[0xff; 32]` *does* decompress, since the top bit is the sign of `x`
    /// and the remaining 255 bits are reduced modulo `p`. Only about half of all
    /// field elements are valid `y` coordinates, so a short scan always finds one.
    fn not_a_point() -> [u8; 32] {
        for candidate in 0..=u8::MAX {
            let mut bytes = [0_u8; 32];
            bytes[0] = candidate;
            if CompressedEdwardsY(bytes).decompress().is_none() {
                return bytes;
            }
        }
        panic!("no non-decompressable encoding found in 256 candidates");
    }

    #[test]
    fn malformed_keys_are_rejected() {
        assert_eq!(
            PublicKey::from_bytes(not_a_point()),
            Err(Error::MalformedPublicKey)
        );

        // Every low-order encoding must go, not just the identity: a small-order
        // key would give the log the same search key for every label.
        let identity = {
            let mut bytes = [0_u8; 32];
            bytes[0] = 1;
            bytes
        };
        let order_two = {
            let mut bytes = [0xff_u8; 32];
            bytes[0] = 0xec;
            bytes[31] = 0x7f;
            bytes
        };
        for (name, bytes) in [
            ("identity", identity),
            ("order 4", [0_u8; 32]),
            ("order 2", order_two),
        ] {
            assert_eq!(
                PublicKey::from_bytes(bytes),
                Err(Error::SmallOrderPublicKey),
                "{name} was accepted as a public key"
            );
        }
    }

    #[test]
    fn malformed_proofs_are_rejected() {
        assert_eq!(
            Proof::from_slice(&[0; 79]),
            Err(Error::ProofLength {
                expected: 80,
                actual: 79
            })
        );

        let secret = SecretKey::from_seed([8; 32]);
        let (_, proof) = secret.prove_raw(SUITE, b"x").unwrap();
        let mut bytes = *proof.as_bytes();
        bytes[..PT_LEN].copy_from_slice(&not_a_point());
        assert_eq!(
            secret
                .public_key()
                .verify_raw(SUITE, b"x", &Proof::from_bytes(bytes)),
            Err(Error::MalformedGamma)
        );
    }

    /// The P-256 suite is not implemented, and asking for it says so instead of
    /// evaluating the wrong curve.
    #[test]
    fn p256_suite_is_refused() {
        let secret = SecretKey::from_seed([9; 32]);
        let suite = CipherSuite::Kt128Sha256P256;
        assert_eq!(
            secret.prove_raw(suite, b"x"),
            Err(Error::UnsupportedSuite { suite })
        );
    }

    /// A label above the `2^8-1` ceiling of §11.7 cannot be encoded, so it cannot
    /// be silently truncated into a different label's search key.
    #[test]
    fn over_long_labels_are_refused() {
        let secret = SecretKey::from_seed([10; 32]);
        let input = VrfInput::new(vec![0x61; 256], 0);
        assert!(matches!(
            secret.evaluate(SUITE, &input),
            Err(Error::Wire(_))
        ));
    }

    /// The secret key must not leak through its own Debug output.
    #[test]
    fn debug_does_not_print_key_material() {
        let secret = SecretKey::from_seed([0xab; 32]);
        let rendered = alloc::format!("{secret:?}");
        assert!(!rendered.contains("ab"), "{rendered}");
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail loudly by panicking; the lint protects library paths"
)]
mod error_tests {
    use super::*;
    use alloc::string::ToString as _;

    /// Every variant renders. Two of them deliberately carry no detail —
    /// [`Error::BadProof`] and [`Error::SmallOrderPublicKey`] — because which byte of a
    /// proof failed is not information to hand back to whoever supplied it.
    #[test]
    fn every_error_renders() {
        use core::error::Error as _;

        let cases: [(Error, &[&str]); 8] = [
            (
                Error::UnsupportedSuite {
                    suite: CipherSuite::Kt128Sha256P256,
                },
                &["KT_128_SHA256_P256", "not implemented"],
            ),
            (Error::MalformedPublicKey, &["public key"]),
            (Error::SmallOrderPublicKey, &["small order"]),
            (
                Error::ProofLength {
                    expected: 80,
                    actual: 79,
                },
                &["80", "79"],
            ),
            (Error::MalformedGamma, &["Gamma"]),
            (Error::NonCanonicalScalar, &["canonical"]),
            (Error::BadProof, &["does not verify"]),
            (
                Error::Wire(codec::Error::VectorTooLong {
                    count: 256,
                    max: 255,
                }),
                &["256", "255"],
            ),
        ];
        for (error, needles) in cases {
            let rendered = error.to_string();
            for needle in needles {
                assert!(rendered.contains(needle), "{rendered:?} omits {needle:?}");
            }
        }

        // Only the wrapping variant chains.
        assert!(
            Error::Wire(codec::Error::TrailingBytes { remaining: 1 })
                .source()
                .is_some()
        );
        assert!(Error::BadProof.source().is_none());
    }

    #[test]
    fn codec_errors_convert() {
        let converted: Error = codec::Error::TrailingBytes { remaining: 2 }.into();
        assert!(matches!(converted, Error::Wire(_)));
    }

    /// The accessors a caller uses to get a search key out of an output, and a proof
    /// on and off the wire.
    #[test]
    fn outputs_and_proofs_expose_their_bytes() {
        let secret = SecretKey::from_seed([0x33; SECRET_KEY_SIZE]);
        assert_eq!(secret.seed(), &[0x33; SECRET_KEY_SIZE]);

        let (output, proof) = secret
            .evaluate(
                CipherSuite::Kt128Sha256Ed25519,
                &VrfInput::new(b"x".to_vec(), 0),
            )
            .unwrap();

        // The search key is the output, and it is what the prefix tree is indexed by.
        assert_eq!(output.search_key().as_bytes(), output.as_bytes());
        assert_eq!(output.as_bytes().len(), OUTPUT_SIZE);

        assert_eq!(Proof::from_bytes(*proof.as_bytes()), proof);
        assert_eq!(Proof::from_slice(proof.as_bytes()).unwrap(), proof);

        // A public key round-trips through its encoding.
        let public = *secret.public_key();
        assert_eq!(PublicKey::from_bytes(*public.as_bytes()).unwrap(), public);
    }

    /// The P-256 suite is refused on the verifying side too, not only when proving.
    #[test]
    fn p256_is_refused_when_verifying() {
        let secret = SecretKey::from_seed([0x44; SECRET_KEY_SIZE]);
        let suite = CipherSuite::Kt128Sha256Ed25519;
        let input = VrfInput::new(b"y".to_vec(), 0);
        let (_, proof) = secret.evaluate(suite, &input).unwrap();

        let p256 = CipherSuite::Kt128Sha256P256;
        assert_eq!(
            secret.public_key().verify(p256, &input, &proof),
            Err(Error::UnsupportedSuite { suite: p256 })
        );
    }
}
