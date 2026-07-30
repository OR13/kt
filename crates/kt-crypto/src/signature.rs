//! Tree head signatures
//! (`draft-ietf-keytrans-protocol-05` §11.2, §11.3, §11.4).
//!
//! Everything else in this workspace computes a value and compares it. This is the
//! first module where verification depends on a key the log chose, which makes it
//! the point where "the bytes agree" turns into "the log said so". A client that
//! verifies a `TreeHeadTBS` signature has bound the log to one root for one tree
//! size under one configuration; nothing below this layer can do that.
//!
//! # What is signed
//!
//! Not the [`TreeHead`] but the [`TreeHeadTBS`] — configuration, tree size, root —
//! and the configuration comes first. So the signature covers the log's cipher
//! suite, deployment mode, and every public key it publishes, which is what stops a
//! log from reusing a signature under a changed configuration. It also means a
//! disagreement about how a `Configuration` encodes breaks every signature; see
//! [`kt_wire::heads`] for one such disagreement between the two Go peers.
//!
//! # Both registered suites
//!
//! Ed25519 (RFC 8032) for `KT_128_SHA256_Ed25519`, and ECDSA/P-256 over SHA-256 for
//! `KT_128_SHA256_P256`. §17.1 fixes the latter's encoding as "the concatenation of
//! two 256-bit big endian integers r and s", so 64 fixed-width bytes rather than the
//! ASN.1 sequence ECDSA usually travels in.
//!
//! The two suites also differ in how the *key* is encoded, which §11.2 does not say:
//! the peer emits an Ed25519 key as its 32 raw bytes and a P-256 signature key
//! uncompressed (65 bytes, SEC1 tag `0x04`), while the same `Configuration` carries a
//! P-256 *VRF* key compressed (33 bytes). Rather than fix a length, the P-256 path
//! accepts whatever SEC1 admits; `tree-head.json` pins what the peer sends.

use alloc::vec::Vec;

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use kt_wire::codec;
use kt_wire::heads::{
    AuditorTreeHead, AuditorTreeHeadTBS, Configuration, FullTreeHead, TreeHead, TreeHeadTBS,
};
use kt_wire::structs::HashValue;

use crate::suite::CipherSuite;

/// An Ed25519 public key's length in bytes.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// An Ed25519 signature's length in bytes.
pub const SIGNATURE_SIZE: usize = 64;

/// Something wrong with a signature, a key, or the head being verified.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The cipher suite's signature algorithm is not implemented here.
    UnsupportedSuite {
        /// The suite asked for.
        suite: CipherSuite,
    },
    /// The configuration named a cipher suite this build does not know.
    UnknownCipherSuite {
        /// The registry value the configuration carried.
        value: u16,
    },
    /// A public key was not a valid Ed25519 encoding.
    MalformedPublicKey,
    /// A signature was not 64 bytes, or not a valid Ed25519 encoding.
    MalformedSignature,
    /// The signature did not verify over the structure it should cover.
    BadSignature,
    /// A head claimed a tree size that contradicts what it is being checked
    /// against.
    ///
    /// §11.4 step 2.1: an `updated` head must be strictly larger than the size the
    /// user advertised. §11.3 step 3: an auditor may not claim a larger tree than
    /// the log itself.
    TreeSize {
        /// The size the head claimed.
        claimed: u64,
        /// The size it must improve on or stay within.
        bound: u64,
    },
    /// A `thirdPartyAuditing` configuration was verified without the auditor's
    /// parameters, or an auditor head arrived under a mode that has no auditor.
    AuditorMismatch,
    /// A structure could not be encoded for signing.
    Wire(codec::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedSuite { suite } => {
                write!(f, "signatures for {suite} are not implemented")
            }
            Self::UnknownCipherSuite { value } => {
                write!(f, "configuration names unknown cipher suite 0x{value:04x}")
            }
            Self::MalformedPublicKey => f.write_str("signature public key is not a valid key"),
            Self::MalformedSignature => f.write_str("signature is not a valid encoding"),
            Self::BadSignature => f.write_str("signature does not verify"),
            Self::TreeSize { claimed, bound } => {
                write!(
                    f,
                    "tree size {claimed} is not permitted against the bound {bound}"
                )
            }
            Self::AuditorMismatch => f.write_str(
                "auditor head and deployment mode disagree about whether there is an auditor",
            ),
            Self::Wire(err) => write!(f, "encoding: {err}"),
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

/// A specialized [`Result`] for signature operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Verifies `signature` over `message` with the suite's signature algorithm.
///
/// # Errors
///
/// [`Error::UnsupportedSuite`], [`Error::MalformedPublicKey`],
/// [`Error::MalformedSignature`], or [`Error::BadSignature`].
pub fn verify_raw(
    suite: CipherSuite,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    match suite {
        // ECDSA/P-256 over SHA-256, whose signatures are "the concatenation of two
        // 256-bit big endian integers r and s" (§17.1) — so 64 fixed-width bytes,
        // not the ASN.1 sequence ECDSA is usually seen in.
        //
        // Note the two key encodings this suite uses. The *signature* key arrives
        // uncompressed (65 bytes, SEC1 tag 0x04), because that is what the peer's
        // `ParseSigningPublicKey` accepts and what its `Bytes()` emits; the *VRF*
        // key arrives compressed (33 bytes). Both live in the same `Configuration`,
        // as `opaque signature_public_key<0..2^16-1>` and
        // `opaque vrf_public_key<0..2^16-1>`, and §11.2 says nothing about either
        // encoding — so this accepts whatever SEC1 admits rather than fixing a
        // length, and `tree-head.json` pins what the peer actually sends.
        CipherSuite::Kt128Sha256P256 => {
            use p256::ecdsa::signature::Verifier as _;

            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| Error::MalformedPublicKey)?;
            let signature = p256::ecdsa::Signature::from_slice(signature)
                .map_err(|_| Error::MalformedSignature)?;
            // `Verifier` hashes with the curve's associated digest, SHA-256, which is
            // also the suite's hash — unlike the VRF, where the two differ.
            key.verify(message, &signature)
                .map_err(|_| Error::BadSignature)
        }
        CipherSuite::Kt128Sha256Ed25519 => {
            let key_bytes = <[u8; PUBLIC_KEY_SIZE]>::try_from(public_key)
                .map_err(|_| Error::MalformedPublicKey)?;
            let key =
                VerifyingKey::from_bytes(&key_bytes).map_err(|_| Error::MalformedPublicKey)?;
            let signature_bytes = <[u8; SIGNATURE_SIZE]>::try_from(signature)
                .map_err(|_| Error::MalformedSignature)?;
            let signature = Signature::from_bytes(&signature_bytes);

            // `verify` is the strict variant in ed25519-dalek: it rejects
            // small-order public keys and non-canonical signature scalars, which is
            // what stops one signature from verifying under several encodings.
            key.verify(message, &signature)
                .map_err(|_| Error::BadSignature)
        }
    }
}

/// The cipher suite a configuration names.
///
/// # Errors
///
/// [`Error::UnknownCipherSuite`] if the value is not in the §17.1 registry.
pub fn suite_of(config: &Configuration) -> Result<CipherSuite> {
    CipherSuite::from_code(config.cipher_suite).map_err(|_| Error::UnknownCipherSuite {
        value: config.cipher_suite,
    })
}

/// Verifies a [`TreeHead`] against the configuration that published its key
/// (§11.2, and step 2.2 of §11.4).
///
/// `root` is the log tree root the client computed for `head.tree_size` — the
/// signature is only meaningful against a root the client derived itself, which is
/// why this takes one rather than reading it from the head.
///
/// # Errors
///
/// [`Error::BadSignature`] if the signature does not cover this configuration, size,
/// and root, plus the key and suite errors of [`verify_raw`].
pub fn verify_tree_head(config: &Configuration, head: &TreeHead, root: HashValue) -> Result<()> {
    let suite = suite_of(config)?;
    let tbs = TreeHeadTBS {
        config: config.clone(),
        tree_size: head.tree_size,
        root,
    };
    let message = encode(&tbs)?;
    verify_raw(
        suite,
        &config.signature_public_key,
        &message,
        &head.signature,
    )
}

/// Verifies an [`AuditorTreeHead`] (§11.3, steps 3 and 4).
///
/// `log_tree_size` is the size the log's own `TreeHead` claimed, and `root` is the
/// root the client computed at the auditor's `tree_size`. Step 3's check — that an
/// auditor may not claim a larger tree than the log — is enforced here; steps 1 and
/// 2 involve the client's retained state and its clock, so they belong to the
/// algorithms in `kt-client` rather than here.
///
/// # Errors
///
/// [`Error::AuditorMismatch`] if the configuration has no auditor,
/// [`Error::TreeSize`] if the auditor claims more than the log, plus signature
/// errors.
pub fn verify_auditor_tree_head(
    config: &Configuration,
    head: &AuditorTreeHead,
    log_tree_size: u64,
    root: HashValue,
) -> Result<()> {
    let suite = suite_of(config)?;
    let auditor = config.auditor.as_ref().ok_or(Error::AuditorMismatch)?;

    // §11.3 step 3.
    if head.tree_size > log_tree_size {
        return Err(Error::TreeSize {
            claimed: head.tree_size,
            bound: log_tree_size,
        });
    }

    let tbs = AuditorTreeHeadTBS {
        config: config.clone(),
        timestamp: head.timestamp,
        tree_size: head.tree_size,
        root,
    };
    let message = encode(&tbs)?;
    verify_raw(
        suite,
        &auditor.auditor_public_key,
        &message,
        &head.signature,
    )
}

/// What a client knows about the tree head it already had, for §11.4's checks.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Advertised {
    /// The tree size the client advertised, if any.
    pub tree_size: Option<u64>,
}

/// Verifies a [`FullTreeHead`] as far as cryptography can (§11.4).
///
/// Returns the [`TreeHead`] the client should now hold, or `None` when the log
/// elected to keep using the head the client advertised.
///
/// `root_at` supplies the log tree root for a given size: §11.4's signature checks
/// are only meaningful against roots the client derived from proofs it verified, so
/// this asks for them rather than accepting them.
///
/// What is **not** checked here, because it is not cryptographic: §11.4 step 1 and
/// step 2's timestamp bounds, which need the client's clock and its retained
/// frontier. Those belong to `kt-client`, and this function's contract is
/// deliberately narrower than §11.4's list so that the gap is visible rather than
/// assumed closed.
///
/// # Errors
///
/// [`Error::TreeSize`] if an `updated` head does not improve on the advertised size
/// (step 2.1), [`Error::AuditorMismatch`] if the auditor head and the mode disagree,
/// plus signature errors.
pub fn verify_full_tree_head(
    config: &Configuration,
    full: &FullTreeHead,
    advertised: Advertised,
    root_at: impl Fn(u64) -> Option<HashValue>,
) -> Result<Option<TreeHead>> {
    match full {
        // Step 1's remaining checks are the client's; there is no signature here.
        FullTreeHead::Same => {
            if advertised.tree_size.is_none() {
                // §11.4 step 1: `same` is only meaningful if the user advertised a
                // size to keep using.
                return Err(Error::TreeSize {
                    claimed: 0,
                    bound: 0,
                });
            }
            Ok(None)
        }
        FullTreeHead::Updated {
            tree_head,
            auditor_tree_head,
        } => {
            // Step 2.1.
            if let Some(previous) = advertised.tree_size {
                if tree_head.tree_size <= previous {
                    return Err(Error::TreeSize {
                        claimed: tree_head.tree_size,
                        bound: previous,
                    });
                }
            }

            // Step 2.2.
            let root = root_at(tree_head.tree_size).ok_or(Error::BadSignature)?;
            verify_tree_head(config, tree_head, root)?;

            // Step 2.3. The mode decides whether an auditor head belongs here at
            // all, so a head that arrives in the wrong mode is a mismatch rather
            // than something to ignore.
            match (auditor_tree_head, Configuration::auditor_modes(config.mode)) {
                (None, false) => {}
                (Some(auditor), true) => {
                    let auditor_root = root_at(auditor.tree_size).ok_or(Error::BadSignature)?;
                    verify_auditor_tree_head(config, auditor, tree_head.tree_size, auditor_root)?;
                }
                _ => return Err(Error::AuditorMismatch),
            }

            Ok(Some(tree_head.clone()))
        }
    }
}

/// Encodes a structure for signing.
fn encode<T: kt_wire::codec::Encode>(value: &T) -> Result<Vec<u8>> {
    let mut enc = codec::Encoder::new();
    value.encode(&mut enc)?;
    Ok(enc.into_bytes())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests fail loudly by panicking; the lints protect library paths"
)]
mod tests {
    use super::*;
    use alloc::vec;
    use ed25519_dalek::{Signer as _, SigningKey};
    use kt_wire::heads::AuditorConfig;
    use kt_wire::structs::DeploymentMode;

    const SUITE: CipherSuite = CipherSuite::Kt128Sha256Ed25519;

    fn keys(seed: u8) -> (SigningKey, Vec<u8>) {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let public = signing.verifying_key().to_bytes().to_vec();
        (signing, public)
    }

    fn config(mode: DeploymentMode, log: &[u8], auditor: Option<&[u8]>) -> Configuration {
        Configuration {
            cipher_suite: SUITE.code(),
            mode,
            signature_public_key: log.to_vec(),
            vrf_public_key: vec![0xbb; 32],
            leaf_public_key: Configuration::leaf_public_key_modes(mode).then(|| vec![0xcc; 32]),
            auditor: auditor.map(|key| AuditorConfig {
                max_auditor_lag: 60_000,
                auditor_start_pos: 0,
                auditor_public_key: key.to_vec(),
            }),
            max_ahead: 10_000,
            max_behind: 10_000,
            reasonable_monitoring_window: 604_800_000,
            maximum_lifetime: None,
        }
    }

    fn root(byte: u8) -> HashValue {
        HashValue::from_bytes([byte; 32])
    }

    fn signed_head(
        signing: &SigningKey,
        config: &Configuration,
        size: u64,
        r: HashValue,
    ) -> TreeHead {
        let tbs = TreeHeadTBS {
            config: config.clone(),
            tree_size: size,
            root: r,
        };
        let message = encode(&tbs).unwrap();
        TreeHead {
            tree_size: size,
            signature: signing.sign(&message).to_bytes().to_vec(),
        }
    }

    /// The signature covers the configuration, the size, and the root — so changing
    /// any of the three has to break it. That is the property §11.2 exists for.
    #[test]
    fn a_tree_head_signature_binds_config_size_and_root() {
        let (signing, public) = keys(1);
        let cfg = config(DeploymentMode::ContactMonitoring, &public, None);
        let head = signed_head(&signing, &cfg, 50, root(0x11));

        verify_tree_head(&cfg, &head, root(0x11)).unwrap();

        // A different root.
        assert_eq!(
            verify_tree_head(&cfg, &head, root(0x12)),
            Err(Error::BadSignature)
        );

        // A different size, with the signature unchanged.
        let mut resized = head.clone();
        resized.tree_size = 51;
        assert_eq!(
            verify_tree_head(&cfg, &resized, root(0x11)),
            Err(Error::BadSignature)
        );

        // A different configuration: every field of it is covered, so changing the
        // monitoring window is enough.
        let mut altered = cfg.clone();
        altered.reasonable_monitoring_window += 1;
        assert_eq!(
            verify_tree_head(&altered, &head, root(0x11)),
            Err(Error::BadSignature)
        );

        // And a different mode, which is the case that would let a log move between
        // deployment models while reusing signatures.
        let mut remoded = cfg.clone();
        remoded.mode = DeploymentMode::ThirdPartyManagement;
        assert_eq!(
            verify_tree_head(&remoded, &head, root(0x11)),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn signatures_are_bound_to_their_key() {
        let (signing, public) = keys(2);
        let (_, other_public) = keys(3);
        let cfg = config(DeploymentMode::ContactMonitoring, &public, None);
        let head = signed_head(&signing, &cfg, 8, root(0x22));

        let mut wrong_key = cfg.clone();
        wrong_key.signature_public_key = other_public;
        assert_eq!(
            verify_tree_head(&wrong_key, &head, root(0x22)),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn every_bit_flip_in_a_signature_is_rejected() {
        let (signing, public) = keys(4);
        let cfg = config(DeploymentMode::ContactMonitoring, &public, None);
        let head = signed_head(&signing, &cfg, 4, root(0x33));

        for byte in 0..SIGNATURE_SIZE {
            let mut broken = head.clone();
            broken.signature[byte] ^= 0x01;
            assert!(
                verify_tree_head(&cfg, &broken, root(0x33)).is_err(),
                "flipping byte {byte} still verified"
            );
        }
    }

    #[test]
    fn malformed_keys_and_signatures_are_rejected() {
        let (signing, public) = keys(5);
        let cfg = config(DeploymentMode::ContactMonitoring, &public, None);
        let head = signed_head(&signing, &cfg, 4, root(0x44));

        let mut short_key = cfg.clone();
        short_key.signature_public_key = vec![0; 31];
        assert_eq!(
            verify_tree_head(&short_key, &head, root(0x44)),
            Err(Error::MalformedPublicKey)
        );

        let mut short_signature = head.clone();
        short_signature.signature.pop();
        assert_eq!(
            verify_tree_head(&cfg, &short_signature, root(0x44)),
            Err(Error::MalformedSignature)
        );

        let mut unknown_suite = cfg.clone();
        unknown_suite.cipher_suite = 0xf00d;
        assert_eq!(
            verify_tree_head(&unknown_suite, &head, root(0x44)),
            Err(Error::UnknownCipherSuite { value: 0xf00d })
        );

        // An Ed25519 key and signature offered to the P-256 path: 32 bytes is not a SEC1
        // point, so it stops at the key rather than being fed to the wrong curve.
        assert_eq!(
            verify_raw(CipherSuite::Kt128Sha256P256, &public, b"m", &head.signature),
            Err(Error::MalformedPublicKey)
        );
    }

    /// §11.3 step 3: an auditor may not claim a larger tree than the log.
    #[test]
    fn an_auditor_cannot_claim_more_than_the_log() {
        let (log_signing, log_public) = keys(6);
        let (auditor_signing, auditor_public) = keys(7);
        let cfg = config(
            DeploymentMode::ThirdPartyAuditing,
            &log_public,
            Some(&auditor_public),
        );

        let sign_auditor = |size: u64, r: HashValue| {
            let tbs = AuditorTreeHeadTBS {
                config: cfg.clone(),
                timestamp: 1_700_000_000_000,
                tree_size: size,
                root: r,
            };
            let message = encode(&tbs).unwrap();
            AuditorTreeHead {
                timestamp: 1_700_000_000_000,
                tree_size: size,
                signature: auditor_signing.sign(&message).to_bytes().to_vec(),
            }
        };

        let head = sign_auditor(8, root(0x55));
        verify_auditor_tree_head(&cfg, &head, 10, root(0x55)).unwrap();
        verify_auditor_tree_head(&cfg, &head, 8, root(0x55)).unwrap();
        assert_eq!(
            verify_auditor_tree_head(&cfg, &head, 7, root(0x55)),
            Err(Error::TreeSize {
                claimed: 8,
                bound: 7
            }),
            "the auditor claims a tree the log does not have"
        );

        // The log's own key must not verify the auditor's head.
        let impostor = {
            let tbs = AuditorTreeHeadTBS {
                config: cfg.clone(),
                timestamp: 1_700_000_000_000,
                tree_size: 8,
                root: root(0x55),
            };
            let message = encode(&tbs).unwrap();
            AuditorTreeHead {
                timestamp: 1_700_000_000_000,
                tree_size: 8,
                signature: log_signing.sign(&message).to_bytes().to_vec(),
            }
        };
        assert_eq!(
            verify_auditor_tree_head(&cfg, &impostor, 10, root(0x55)),
            Err(Error::BadSignature),
            "the log signing in the auditor's place must not pass"
        );

        // A mode with no auditor cannot verify one.
        let plain = config(DeploymentMode::ContactMonitoring, &log_public, None);
        assert_eq!(
            verify_auditor_tree_head(&plain, &head, 10, root(0x55)),
            Err(Error::AuditorMismatch)
        );
    }

    /// §11.4, including step 2.1: an updated head has to be strictly newer.
    #[test]
    fn full_tree_heads_follow_11_4() {
        let (signing, public) = keys(8);
        let cfg = config(DeploymentMode::ContactMonitoring, &public, None);
        let head = signed_head(&signing, &cfg, 50, root(0x66));
        let roots = |size: u64| (size == 50).then(|| root(0x66));

        let updated = FullTreeHead::Updated {
            tree_head: head.clone(),
            auditor_tree_head: None,
        };

        // With nothing advertised, any signed head is acceptable.
        assert_eq!(
            verify_full_tree_head(&cfg, &updated, Advertised::default(), roots).unwrap(),
            Some(head.clone())
        );

        // Advertising a smaller size is fine; the same size or larger is not.
        let advertised = |size: u64| Advertised {
            tree_size: Some(size),
        };
        assert!(verify_full_tree_head(&cfg, &updated, advertised(49), roots).is_ok());
        assert_eq!(
            verify_full_tree_head(&cfg, &updated, advertised(50), roots),
            Err(Error::TreeSize {
                claimed: 50,
                bound: 50
            }),
            "step 2.1 requires strictly greater"
        );
        assert_eq!(
            verify_full_tree_head(&cfg, &updated, advertised(51), roots),
            Err(Error::TreeSize {
                claimed: 50,
                bound: 51
            })
        );

        // `same` is only meaningful when a size was advertised.
        assert_eq!(
            verify_full_tree_head(&cfg, &FullTreeHead::Same, advertised(50), roots).unwrap(),
            None
        );
        assert!(
            verify_full_tree_head(&cfg, &FullTreeHead::Same, Advertised::default(), roots).is_err()
        );

        // A client that cannot supply the root for the claimed size cannot verify
        // the signature, and must not be told the head is good.
        let no_roots = |_: u64| None;
        assert_eq!(
            verify_full_tree_head(&cfg, &updated, Advertised::default(), no_roots),
            Err(Error::BadSignature)
        );
    }

    /// An auditor head arriving in a mode without an auditor, and missing when the
    /// mode requires one: both are mismatches rather than things to ignore.
    #[test]
    fn auditor_heads_must_match_the_mode() {
        let (signing, public) = keys(9);
        let (auditor_signing, auditor_public) = keys(10);
        let plain = config(DeploymentMode::ContactMonitoring, &public, None);
        let audited = config(
            DeploymentMode::ThirdPartyAuditing,
            &public,
            Some(&auditor_public),
        );

        let head = signed_head(&signing, &plain, 4, root(0x77));
        let auditor_head = {
            let tbs = AuditorTreeHeadTBS {
                config: audited.clone(),
                timestamp: 1,
                tree_size: 4,
                root: root(0x77),
            };
            let message = encode(&tbs).unwrap();
            AuditorTreeHead {
                timestamp: 1,
                tree_size: 4,
                signature: auditor_signing.sign(&message).to_bytes().to_vec(),
            }
        };
        let roots = |_: u64| Some(root(0x77));

        // An auditor head under contact monitoring.
        let wrong = FullTreeHead::Updated {
            tree_head: head.clone(),
            auditor_tree_head: Some(auditor_head.clone()),
        };
        assert_eq!(
            verify_full_tree_head(&plain, &wrong, Advertised::default(), roots),
            Err(Error::AuditorMismatch)
        );

        // And no auditor head under third-party auditing.
        let audited_head = signed_head(&signing, &audited, 4, root(0x77));
        let missing = FullTreeHead::Updated {
            tree_head: audited_head.clone(),
            auditor_tree_head: None,
        };
        assert_eq!(
            verify_full_tree_head(&audited, &missing, Advertised::default(), roots),
            Err(Error::AuditorMismatch)
        );

        // With both present and the mode right, it verifies.
        let good = FullTreeHead::Updated {
            tree_head: audited_head,
            auditor_tree_head: Some(auditor_head),
        };
        assert!(verify_full_tree_head(&audited, &good, Advertised::default(), roots).is_ok());
    }

    #[test]
    fn errors_render_and_chain() {
        use alloc::string::ToString as _;
        use core::error::Error as _;

        let cases: [(Error, &[&str]); 7] = [
            (
                Error::UnsupportedSuite {
                    suite: CipherSuite::Kt128Sha256P256,
                },
                &["KT_128_SHA256_P256"],
            ),
            (Error::UnknownCipherSuite { value: 0xf00d }, &["f00d"]),
            (Error::MalformedPublicKey, &["public key"]),
            (Error::MalformedSignature, &["signature"]),
            (Error::BadSignature, &["does not verify"]),
            (
                Error::TreeSize {
                    claimed: 8,
                    bound: 7,
                },
                &["8", "7"],
            ),
            (Error::AuditorMismatch, &["auditor"]),
        ];
        for (error, needles) in cases {
            let rendered = error.to_string();
            for needle in needles {
                assert!(rendered.contains(needle), "{rendered:?} omits {needle:?}");
            }
            assert!(error.source().is_none());
        }

        let wire = Error::Wire(codec::Error::TrailingBytes { remaining: 1 });
        assert!(wire.source().is_some());
    }
}
