//! Tree heads and the log's configuration
//! (`draft-ietf-keytrans-protocol-05` §11.2, §11.3, §11.4).
//!
//! A [`TreeHead`] is what the Transparency Log signs, and [`Configuration`] is the
//! long-term state that every one of those signatures covers. The signature is over
//! a [`TreeHeadTBS`], which begins with the whole `Configuration` — so any
//! disagreement about how a configuration encodes is a disagreement about every
//! signature the log has ever produced.
//!
//! # A disagreement about §11.2, found by comparing implementations — since resolved
//!
//! **Resolved on 2026-07-28: the draft deleted `case contactMonitoring:`, which is the reading
//! this module implements.** The account below is kept because the negative vector in
//! `tree-head.json` — a signature valid only under the other reading — still guards the choice,
//! and because the reasoning is what a future grouped `select` should be read against.
//!
//! §11.2 used to write the mode-dependent part of `Configuration` as:
//!
//! ```tls-presentation
//! select (Configuration.mode) {
//!   case contactMonitoring:
//!   case thirdPartyManagement:
//!     opaque leaf_public_key<0..2^16-1>;
//!   case thirdPartyAuditing:
//!     uint64 max_auditor_lag;
//!     uint64 auditor_start_pos;
//!     opaque auditor_public_key<0..2^16-1>;
//! };
//! ```
//!
//! Read as grouped cases — the C-derived convention the presentation language
//! inherits — `contactMonitoring` and `thirdPartyManagement` share a body, so
//! `leaf_public_key` is present in **both**. The two Go implementations read this
//! differently: `katie` emits `leaf_public_key` only under `thirdPartyManagement`,
//! while `keytrans-verification` records the field as "Only for Contact monitoring
//! or ThirdParty".
//!
//! This is not cosmetic. In `contactMonitoring` mode the two readings produce
//! `Configuration` encodings that differ by a length-prefixed key, so every
//! `TreeHeadTBS` differs, so **no signature verifies across the two**.
//!
//! The draft's own prose settles it in katie's favour: "If the deployment mode
//! specifies a Third-Party Manager, a public key is provided in `leaf_public_key`.
//! This public key is used to verify the Service Operator's signature on
//! modifications" — and §11.5 gives `UpdateSuffix` a signature only under
//! `thirdPartyManagement`, so under contact monitoring the key would have nothing
//! to verify. So the `case contactMonitoring:` label looks like an editing slip.
//!
//! This module followed katie and the prose, because that is what interoperated and
//! what made semantic sense. [`Configuration::leaf_public_key_modes`] states the
//! rule in one place, and `interop/vectors/tree-head.json` pins it in all three
//! modes so the choice is checked rather than assumed. The draft has since said the
//! same, so nothing here changes; had it gone the other way, that function and its
//! vector would have.

use alloc::vec::Vec;

use crate::codec::{Decode, Decoder, Encode, Encoder, Error, Result, VectorSpec};
use crate::structs::{DeploymentMode, HashValue};

/// A public key as it appears in a `Configuration`: `opaque key<0..2^16-1>`.
pub const PUBLIC_KEY: VectorSpec = VectorSpec::new((1 << 16) - 1);

/// A signature: `opaque signature<0..2^16-1>`.
pub const SIGNATURE: VectorSpec = VectorSpec::new((1 << 16) - 1);

/// The Third-Party Auditor's parameters, present under `thirdPartyAuditing` (§11.2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditorConfig {
    /// How far behind the log the auditor may be, in milliseconds.
    pub max_auditor_lag: u64,
    /// The first log entry the auditor started processing.
    pub auditor_start_pos: u64,
    /// The key that verifies the auditor's signatures.
    pub auditor_public_key: Vec<u8>,
}

/// The Transparency Log's long-term configuration (§11.2 `Configuration`).
///
/// Every tree head signature covers this structure, so its encoding is
/// consequential — see the module documentation for a place where two
/// implementations disagree about it.
///
/// No `Default`: `reserved(0)` is not a deployment mode, so there is no
/// configuration to default to, and a half-built one would encode as something.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Configuration {
    /// The `CipherSuite` registry value (§17.1). Left as a `uint16` because this
    /// crate does not depend on the suite definitions.
    pub cipher_suite: u16,
    /// How the log is deployed, which selects the fields below.
    pub mode: DeploymentMode,
    /// The key that verifies `TreeHeadTBS` signatures.
    pub signature_public_key: Vec<u8>,
    /// The key that evaluates VRF proofs (§11.7).
    pub vrf_public_key: Vec<u8>,
    /// The Service Operator's key for signing updates, under
    /// `thirdPartyManagement` (§11.5).
    pub leaf_public_key: Option<Vec<u8>>,
    /// The auditor's parameters, under `thirdPartyAuditing`.
    pub auditor: Option<AuditorConfig>,
    /// How far ahead of the user's clock a tree head may be, in milliseconds.
    pub max_ahead: u64,
    /// How far behind, in milliseconds.
    pub max_behind: u64,
    /// The Reasonable Monitoring Window (§6.1), in milliseconds.
    pub reasonable_monitoring_window: u64,
    /// The maximum lifetime of a log entry (§7.1), if the log defines one.
    pub maximum_lifetime: Option<u64>,
}

impl Configuration {
    /// The modes whose `Configuration` carries a `leaf_public_key`.
    ///
    /// One place, because the alternative reading of §11.2 differs only here — see
    /// the module documentation. Returns `true` only for `thirdPartyManagement`,
    /// following the draft's prose and the peer; the grouped-case reading of the
    /// struct would add `contactMonitoring`.
    #[must_use]
    pub const fn leaf_public_key_modes(mode: DeploymentMode) -> bool {
        matches!(mode, DeploymentMode::ThirdPartyManagement)
    }

    /// Whether this mode carries the auditor parameters.
    #[must_use]
    pub const fn auditor_modes(mode: DeploymentMode) -> bool {
        matches!(mode, DeploymentMode::ThirdPartyAuditing)
    }
}

impl Encode for Configuration {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.u16(self.cipher_suite);
        self.mode.encode(enc)?;
        enc.opaque_vector(PUBLIC_KEY, &self.signature_public_key)?;
        enc.opaque_vector(PUBLIC_KEY, &self.vrf_public_key)?;

        if Self::leaf_public_key_modes(self.mode) {
            // A mode that needs the key but has none is a caller error, and an
            // empty vector is the encoding of "no key" rather than a way to omit
            // the field, so the length prefix still goes out.
            let key = self.leaf_public_key.as_deref().unwrap_or(&[]);
            enc.opaque_vector(PUBLIC_KEY, key)?;
        }
        if Self::auditor_modes(self.mode) {
            let auditor = self.auditor.clone().unwrap_or_default();
            enc.u64(auditor.max_auditor_lag);
            enc.u64(auditor.auditor_start_pos);
            enc.opaque_vector(PUBLIC_KEY, &auditor.auditor_public_key)?;
        }

        enc.u64(self.max_ahead);
        enc.u64(self.max_behind);
        enc.u64(self.reasonable_monitoring_window);
        enc.optional(self.maximum_lifetime.as_ref())
    }
}

impl Decode for Configuration {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        // Self-describing: `mode` is a field of the struct, so unlike the other
        // mode-dependent types here this one needs no external context.
        let cipher_suite = dec.u16()?;
        let mode = DeploymentMode::decode(dec)?;
        let signature_public_key = dec.opaque_vector(PUBLIC_KEY)?.to_vec();
        let vrf_public_key = dec.opaque_vector(PUBLIC_KEY)?.to_vec();

        let leaf_public_key = if Self::leaf_public_key_modes(mode) {
            Some(dec.opaque_vector(PUBLIC_KEY)?.to_vec())
        } else {
            None
        };
        let auditor = if Self::auditor_modes(mode) {
            Some(AuditorConfig {
                max_auditor_lag: dec.u64()?,
                auditor_start_pos: dec.u64()?,
                auditor_public_key: dec.opaque_vector(PUBLIC_KEY)?.to_vec(),
            })
        } else {
            None
        };

        Ok(Self {
            cipher_suite,
            mode,
            signature_public_key,
            vrf_public_key,
            leaf_public_key,
            auditor,
            max_ahead: dec.u64()?,
            max_behind: dec.u64()?,
            reasonable_monitoring_window: dec.u64()?,
            maximum_lifetime: dec.optional()?,
        })
    }
}

/// The head of a Transparency Log (§11.2 `TreeHead`).
///
/// ```tls-presentation
/// struct {
///   uint64 tree_size;
///   opaque signature<0..2^16-1>;
/// } TreeHead;
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TreeHead {
    /// The number of log entries.
    pub tree_size: u64,
    /// A signature over the corresponding [`TreeHeadTBS`].
    pub signature: Vec<u8>,
}

impl Encode for TreeHead {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.u64(self.tree_size);
        enc.opaque_vector(SIGNATURE, &self.signature)
    }
}

impl Decode for TreeHead {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        let tree_size = dec.u64()?;
        let signature = dec.opaque_vector(SIGNATURE)?.to_vec();
        Ok(Self {
            tree_size,
            signature,
        })
    }
}

/// What a [`TreeHead`] signature actually covers (§11.2 `TreeHeadTBS`).
///
/// ```tls-presentation
/// struct {
///   Configuration config;
///   uint64 tree_size;
///   opaque root[Hash.Nh];
/// } TreeHeadTBS;
/// ```
///
/// The configuration comes first, which is why §11.2's ambiguity about
/// `leaf_public_key` reaches every signature rather than just one field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeHeadTBS {
    /// The log's long-term configuration.
    pub config: Configuration,
    /// The number of log entries.
    pub tree_size: u64,
    /// The log tree root at that size.
    pub root: HashValue,
}

impl Encode for TreeHeadTBS {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        self.config.encode(enc)?;
        enc.u64(self.tree_size);
        self.root.encode(enc)
    }
}

impl Decode for TreeHeadTBS {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        let config = Configuration::decode(dec)?;
        let tree_size = dec.u64()?;
        let root = HashValue::decode(dec)?;
        Ok(Self {
            config,
            tree_size,
            root,
        })
    }
}

/// A Third-Party Auditor's view of the log (§11.3 `AuditorTreeHead`).
///
/// ```tls-presentation
/// struct {
///   uint64 timestamp;
///   uint64 tree_size;
///   opaque signature<0..2^16-1>;
/// } AuditorTreeHead;
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditorTreeHead {
    /// When the auditor signed, in milliseconds since the Unix epoch.
    pub timestamp: u64,
    /// The tree size the auditor had seen.
    pub tree_size: u64,
    /// A signature over the corresponding [`AuditorTreeHeadTBS`].
    pub signature: Vec<u8>,
}

impl Encode for AuditorTreeHead {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.u64(self.timestamp);
        enc.u64(self.tree_size);
        enc.opaque_vector(SIGNATURE, &self.signature)
    }
}

impl Decode for AuditorTreeHead {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        let timestamp = dec.u64()?;
        let tree_size = dec.u64()?;
        let signature = dec.opaque_vector(SIGNATURE)?.to_vec();
        Ok(Self {
            timestamp,
            tree_size,
            signature,
        })
    }
}

/// What an [`AuditorTreeHead`] signature covers (§11.3 `AuditorTreeHeadTBS`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditorTreeHeadTBS {
    /// The log's long-term configuration.
    pub config: Configuration,
    /// When the auditor signed.
    pub timestamp: u64,
    /// The tree size the auditor had seen.
    pub tree_size: u64,
    /// The log tree root at that size.
    pub root: HashValue,
}

impl Encode for AuditorTreeHeadTBS {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        self.config.encode(enc)?;
        enc.u64(self.timestamp);
        enc.u64(self.tree_size);
        self.root.encode(enc)
    }
}

impl Decode for AuditorTreeHeadTBS {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        let config = Configuration::decode(dec)?;
        let timestamp = dec.u64()?;
        let tree_size = dec.u64()?;
        let root = HashValue::decode(dec)?;
        Ok(Self {
            config,
            timestamp,
            tree_size,
            root,
        })
    }
}

/// Whether a response carries a new tree head (§11.4 `FullTreeHeadType`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum FullTreeHeadType {
    /// `same(1)`: keep using the tree head the user advertised.
    Same,
    /// `updated(2)`: a newer tree head follows.
    Updated,
}

impl FullTreeHeadType {
    /// The registry value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Same => 1,
            Self::Updated => 2,
        }
    }

    /// Parses a registry value.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEnum`] for `reserved(0)` and anything above 2.
    pub const fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Same),
            2 => Ok(Self::Updated),
            other => Err(Error::InvalidEnum {
                name: "FullTreeHeadType",
                value: other as u64,
            }),
        }
    }
}

/// How tree heads appear on the wire (§11.4 `FullTreeHead`).
///
/// ```tls-presentation
/// struct {
///   FullTreeHeadType head_type;
///   select (FullTreeHead.head_type) {
///     case updated:
///       TreeHead tree_head;
///       select (Configuration.mode) {
///         case thirdPartyAuditing:
///           AuditorTreeHead auditor_tree_head;
///       };
///   };
/// } FullTreeHead;
/// ```
///
/// Two nested selects, one on the head type and one on the deployment mode, which
/// is why decoding takes the mode as an argument: the bytes say whether a head
/// follows, but only the configuration says whether an auditor's head follows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FullTreeHead {
    /// The log is reusing the head the user advertised; no bytes follow the type.
    Same,
    /// A newer head, with the auditor's head when the mode calls for one.
    Updated {
        /// The log's new head.
        tree_head: TreeHead,
        /// The auditor's head, under `thirdPartyAuditing`.
        auditor_tree_head: Option<AuditorTreeHead>,
    },
}

impl FullTreeHead {
    /// This value's type tag.
    #[must_use]
    pub const fn head_type(&self) -> FullTreeHeadType {
        match self {
            Self::Same => FullTreeHeadType::Same,
            Self::Updated { .. } => FullTreeHeadType::Updated,
        }
    }

    /// Reads a `FullTreeHead` as `mode` defines it.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEnum`] for an unknown head type, plus codec errors from the
    /// heads themselves.
    pub fn decode_with_mode(dec: &mut Decoder<'_>, mode: DeploymentMode) -> Result<Self> {
        match FullTreeHeadType::from_u8(dec.u8()?)? {
            FullTreeHeadType::Same => Ok(Self::Same),
            FullTreeHeadType::Updated => {
                let tree_head = TreeHead::decode(dec)?;
                let auditor_tree_head = if Configuration::auditor_modes(mode) {
                    Some(AuditorTreeHead::decode(dec)?)
                } else {
                    None
                };
                Ok(Self::Updated {
                    tree_head,
                    auditor_tree_head,
                })
            }
        }
    }
}

impl Encode for FullTreeHead {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.u8(self.head_type().as_u8());
        if let Self::Updated {
            tree_head,
            auditor_tree_head,
        } = self
        {
            tree_head.encode(enc)?;
            if let Some(auditor) = auditor_tree_head {
                auditor.encode(enc)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "tests fail loudly by panicking; the lints protect the parsing paths"
)]
mod tests {
    use super::*;
    use crate::codec::{decode, encode};
    use alloc::vec;

    fn config(mode: DeploymentMode) -> Configuration {
        Configuration {
            cipher_suite: 2,
            mode,
            signature_public_key: vec![0xaa; 32],
            vrf_public_key: vec![0xbb; 32],
            leaf_public_key: Configuration::leaf_public_key_modes(mode).then(|| vec![0xcc; 32]),
            auditor: Configuration::auditor_modes(mode).then(|| AuditorConfig {
                max_auditor_lag: 1_000,
                auditor_start_pos: 7,
                auditor_public_key: vec![0xdd; 32],
            }),
            max_ahead: 10_000,
            max_behind: 20_000,
            reasonable_monitoring_window: 30_000,
            maximum_lifetime: Some(40_000),
        }
    }

    #[test]
    fn configurations_round_trip_in_every_mode() {
        for mode in [
            DeploymentMode::ContactMonitoring,
            DeploymentMode::ThirdPartyManagement,
            DeploymentMode::ThirdPartyAuditing,
        ] {
            let original = config(mode);
            let bytes = encode(&original).unwrap();
            assert_eq!(
                decode::<Configuration>(&bytes).unwrap(),
                original,
                "{mode:?}"
            );
        }
    }

    /// The §11.2 ambiguity, pinned. Under contact monitoring this implementation
    /// omits `leaf_public_key`, following the draft's prose and the Go peer; the
    /// grouped-case reading of the struct would include it. The two encodings differ
    /// by the key plus its two-byte length prefix, and every `TreeHeadTBS` inherits
    /// the difference — so this test exists to make the choice visible rather than
    /// incidental.
    #[test]
    fn contact_monitoring_omits_the_leaf_public_key() {
        assert!(!Configuration::leaf_public_key_modes(
            DeploymentMode::ContactMonitoring
        ));
        assert!(Configuration::leaf_public_key_modes(
            DeploymentMode::ThirdPartyManagement
        ));
        assert!(!Configuration::leaf_public_key_modes(
            DeploymentMode::ThirdPartyAuditing
        ));

        // A contact-monitoring configuration carrying a key encodes as if it did
        // not: the mode decides, not the field's presence.
        let mut contact = config(DeploymentMode::ContactMonitoring);
        let without = encode(&contact).unwrap();
        contact.leaf_public_key = Some(vec![0xcc; 32]);
        assert_eq!(
            encode(&contact).unwrap(),
            without,
            "the field is not emitted in this mode"
        );

        // What the other reading would produce, for comparison: 34 bytes more.
        let managed = config(DeploymentMode::ThirdPartyManagement);
        let with_key = encode(&managed).unwrap();
        assert_eq!(
            with_key.len(),
            without.len() + 2 + 32,
            "the two readings of §11.2 differ by a length-prefixed key"
        );

        // And decoding ignores whatever a caller put in the field.
        let decoded = decode::<Configuration>(&without).unwrap();
        assert_eq!(decoded.leaf_public_key, None);
    }

    /// The mode-dependent fields appear in the order §11.2 lists them, between the
    /// VRF key and `max_ahead`.
    #[test]
    fn auditor_fields_sit_between_the_keys_and_the_durations() {
        let auditing = config(DeploymentMode::ThirdPartyAuditing);
        let bytes = encode(&auditing).unwrap();
        let contact = encode(&config(DeploymentMode::ContactMonitoring)).unwrap();
        assert_eq!(
            bytes.len(),
            contact.len() + 8 + 8 + 2 + 32,
            "two uint64s and a length-prefixed key"
        );

        // The prefix up to the VRF key is identical in both modes apart from the
        // mode byte itself.
        assert_eq!(&bytes[..2], &contact[..2], "cipher suite");
        assert_ne!(bytes[2], contact[2], "mode");
    }

    #[test]
    fn optional_maximum_lifetime_costs_one_byte_when_absent() {
        let mut cfg = config(DeploymentMode::ContactMonitoring);
        let with = encode(&cfg).unwrap();
        cfg.maximum_lifetime = None;
        let without = encode(&cfg).unwrap();
        assert_eq!(with.len(), without.len() + 8);
        assert_eq!(*without.last().unwrap(), 0x00, "a bare presence octet");
        assert_eq!(
            decode::<Configuration>(&without).unwrap().maximum_lifetime,
            None
        );
    }

    #[test]
    fn tree_heads_and_tbs_round_trip() {
        let head = TreeHead {
            tree_size: 50,
            signature: vec![0x11; 64],
        };
        let bytes = encode(&head).unwrap();
        assert_eq!(bytes.len(), 8 + 2 + 64);
        assert_eq!(decode::<TreeHead>(&bytes).unwrap(), head);

        let tbs = TreeHeadTBS {
            config: config(DeploymentMode::ContactMonitoring),
            tree_size: 50,
            root: HashValue::from_bytes([0x22; 32]),
        };
        let bytes = encode(&tbs).unwrap();
        assert_eq!(decode::<TreeHeadTBS>(&bytes).unwrap(), tbs);

        // The configuration comes first, so a TBS starts with the config's bytes.
        let config_bytes = encode(&tbs.config).unwrap();
        assert_eq!(&bytes[..config_bytes.len()], &config_bytes[..]);
    }

    #[test]
    fn auditor_heads_and_tbs_round_trip() {
        let head = AuditorTreeHead {
            timestamp: 1_700_000_000_000,
            tree_size: 40,
            signature: vec![3; 64],
        };
        let bytes = encode(&head).unwrap();
        assert_eq!(bytes.len(), 8 + 8 + 2 + 64);
        assert_eq!(decode::<AuditorTreeHead>(&bytes).unwrap(), head);

        let tbs = AuditorTreeHeadTBS {
            config: config(DeploymentMode::ThirdPartyAuditing),
            timestamp: 1_700_000_000_000,
            tree_size: 40,
            root: HashValue::from_bytes([0x44; 32]),
        };
        let bytes = encode(&tbs).unwrap();
        assert_eq!(decode::<AuditorTreeHeadTBS>(&bytes).unwrap(), tbs);
    }

    /// §11.4's two nested selects: `same` is a single byte, and whether an auditor's
    /// head follows an `updated` one depends on the mode rather than on the bytes.
    #[test]
    fn full_tree_heads_depend_on_the_mode() {
        let same = FullTreeHead::Same;
        assert_eq!(encode(&same).unwrap(), vec![1]);
        let mut dec = Decoder::new(&[1]);
        assert_eq!(
            FullTreeHead::decode_with_mode(&mut dec, DeploymentMode::ContactMonitoring).unwrap(),
            same
        );

        let tree_head = TreeHead {
            tree_size: 9,
            signature: vec![5; 64],
        };
        let plain = FullTreeHead::Updated {
            tree_head: tree_head.clone(),
            auditor_tree_head: None,
        };
        let bytes = encode(&plain).unwrap();
        let mut dec = Decoder::new(&bytes);
        assert_eq!(
            FullTreeHead::decode_with_mode(&mut dec, DeploymentMode::ContactMonitoring).unwrap(),
            plain
        );
        dec.finish().unwrap();

        let audited = FullTreeHead::Updated {
            tree_head,
            auditor_tree_head: Some(AuditorTreeHead {
                timestamp: 1,
                tree_size: 8,
                signature: vec![6; 64],
            }),
        };
        let bytes = encode(&audited).unwrap();
        let mut dec = Decoder::new(&bytes);
        assert_eq!(
            FullTreeHead::decode_with_mode(&mut dec, DeploymentMode::ThirdPartyAuditing).unwrap(),
            audited
        );
        dec.finish().unwrap();

        // Read in the wrong mode, the auditor's head is left as trailing bytes
        // rather than silently absorbed.
        let mut dec = Decoder::new(&bytes);
        let wrong =
            FullTreeHead::decode_with_mode(&mut dec, DeploymentMode::ContactMonitoring).unwrap();
        assert!(matches!(
            wrong,
            FullTreeHead::Updated {
                auditor_tree_head: None,
                ..
            }
        ));
        assert!(dec.finish().is_err());
    }

    #[test]
    fn reserved_head_types_are_rejected() {
        for value in [0_u8, 3, 255] {
            assert_eq!(
                FullTreeHeadType::from_u8(value),
                Err(Error::InvalidEnum {
                    name: "FullTreeHeadType",
                    value: u64::from(value)
                })
            );
        }
        assert_eq!(FullTreeHeadType::Same.as_u8(), 1);
        assert_eq!(FullTreeHeadType::Updated.as_u8(), 2);
        assert_eq!(FullTreeHead::Same.head_type(), FullTreeHeadType::Same);
    }
}
