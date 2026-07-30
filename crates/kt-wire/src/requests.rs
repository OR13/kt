//! User operation requests and their building blocks
//! (`draft-ietf-keytrans-protocol-05` §13).
//!
//! The request types are self-contained: a client fills one in from what it already
//! knows, so nothing here depends on the algorithms of §6–§10. The *responses* all
//! embed a `CombinedTreeProof`, whose contents are defined by "the order that the
//! algorithm the user is executing would request them" (§12.3) — so those wait for
//! the algorithms, and are deliberately absent from this module rather than stubbed.
//!
//! Also here: the small structures the responses are built from —
//! [`BinaryLadderStep`], [`LabelValue`], [`UpdateInfo`], [`MonitorMapEntry`] — which
//! are self-contained and can be pinned against the peer now.
//!
//! # The one thing to watch
//!
//! Every request starts with `optional<uint64> last`, the tree size the user last
//! observed. It is what makes a response a *consistency* proof rather than a bare
//! assertion, and it is the field §11.4's `head_type` and §4.2's update-view
//! procedure both branch on. A client that omits it is asking the log to tell it
//! whatever it likes.

use alloc::vec::Vec;

use crate::codec::{Decode, Decoder, Encode, Encoder, Result, VectorSpec};
use crate::structs::{HashValue, UpdateSuffix, UpdateValue};

/// `opaque label<0..2^8-1>`, shared by every request in §13.
pub const LABEL: VectorSpec = VectorSpec::new((1 << 8) - 1);

/// One version's worth of a binary ladder response (§13.1 `BinaryLadderStep`).
///
/// ```tls-presentation
/// struct {
///   opaque proof[VRF.Np];
///   optional<HashValue> commitment;
/// } BinaryLadderStep;
/// ```
///
/// `proof` is a VRF proof, so its length is `VRF.Np` — 80 bytes for the Ed25519
/// suite, 81 for P-256 — which is why decoding takes the size rather than reading a
/// length prefix. The commitment is absent exactly when the version does not exist:
/// a step that proves non-inclusion has a VRF proof but nothing to commit to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryLadderStep {
    /// The VRF proof for this version's search key, `VRF.Np` bytes.
    pub proof: Vec<u8>,
    /// The commitment for the version, absent when it does not exist.
    pub commitment: Option<HashValue>,
}

impl BinaryLadderStep {
    /// Reads a step whose VRF proof is `proof_size` bytes (`VRF.Np`).
    ///
    /// # Errors
    ///
    /// Codec errors, including [`crate::codec::Error::InvalidPresence`] if the
    /// commitment's presence octet is neither 0 nor 1.
    pub fn decode_with_proof_size(dec: &mut Decoder<'_>, proof_size: usize) -> Result<Self> {
        let proof = dec.opaque_fixed(proof_size)?.to_vec();
        let commitment = dec.optional()?;
        Ok(Self { proof, commitment })
    }
}

impl Encode for BinaryLadderStep {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        // Fixed-size: the length comes from the cipher suite, not the wire.
        enc.opaque_fixed(&self.proof);
        enc.optional(self.commitment.as_ref())
    }
}

/// A value a user wants to publish for a label (§13.5 `LabelValue`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LabelValue {
    /// The value itself.
    pub value: Vec<u8>,
}

impl LabelValue {
    /// `opaque value<0..2^32-1>`.
    pub const VALUE: VectorSpec = VectorSpec::new((1 << 32) - 1);

    /// A value.
    #[must_use]
    pub fn new(value: impl Into<Vec<u8>>) -> Self {
        Self {
            value: value.into(),
        }
    }
}

impl Encode for LabelValue {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.opaque_vector(Self::VALUE, &self.value)
    }
}

impl Decode for LabelValue {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        Ok(Self {
            value: dec.opaque_vector(Self::VALUE)?.to_vec(),
        })
    }
}

/// What the log returns for each version it created (§13.5 `UpdateInfo`).
///
/// ```tls-presentation
/// struct {
///   opaque opening[Nc];
///   UpdateSuffix suffix;
/// } UpdateInfo;
/// ```
///
/// Two mode- or suite-dependent parts in one small structure: `opening` is `Nc`
/// bytes from the cipher suite, and `suffix` is present only under
/// `thirdPartyManagement`. Neither is discoverable from the bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpdateInfo {
    /// The commitment opening, `Nc` bytes.
    pub opening: Vec<u8>,
    /// The mode-dependent suffix (§11.5).
    pub suffix: UpdateSuffix,
}

impl UpdateInfo {
    /// Reads an `UpdateInfo` whose opening is `nc` bytes, under `mode`.
    ///
    /// # Errors
    ///
    /// Codec errors from the opening or the suffix.
    pub fn decode_with(
        dec: &mut Decoder<'_>,
        nc: usize,
        mode: crate::structs::DeploymentMode,
    ) -> Result<Self> {
        let opening = dec.opaque_fixed(nc)?.to_vec();
        let suffix = UpdateSuffix::decode_with_mode(dec, mode)?;
        Ok(Self { opening, suffix })
    }
}

impl Encode for UpdateInfo {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.opaque_fixed(&self.opening);
        self.suffix.encode(enc)
    }
}

/// One entry of a contact's monitoring state (§13.2 `MonitorMapEntry`).
///
/// ```tls-presentation
/// struct {
///   uint64 position;
///   uint32 version;
/// } MonitorMapEntry;
/// ```
///
/// §13.2 requires the log to check that entries are sorted ascending by `position`,
/// that no `position` or `version` repeats, and that each `position` lies on the
/// direct path of the first log entry containing that version — so this is a
/// structure with real constraints attached, not just a pair.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct MonitorMapEntry {
    /// The log entry position being monitored.
    pub position: u64,
    /// The version of the label at that position.
    pub version: u32,
}

impl Encode for MonitorMapEntry {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.u64(self.position);
        enc.u32(self.version);
        Ok(())
    }
}

impl Decode for MonitorMapEntry {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        let position = dec.u64()?;
        let version = dec.u32()?;
        Ok(Self { position, version })
    }
}

/// A search request (§13.1 `SearchRequest`).
///
/// ```tls-presentation
/// struct {
///   optional<uint64> last;
///   opaque label<0..2^8-1>;
///   optional<uint32> version;
/// } SearchRequest;
/// ```
///
/// `version` absent asks for the greatest version (§6); present asks for that exact
/// version (§7). The two are different algorithms with different proofs, selected by
/// one presence octet.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SearchRequest {
    /// The tree size the user last observed.
    pub last: Option<u64>,
    /// The label being searched for.
    pub label: Vec<u8>,
    /// The exact version wanted, or `None` for the greatest.
    pub version: Option<u32>,
}

impl Encode for SearchRequest {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.optional(self.last.as_ref())?;
        enc.opaque_vector(LABEL, &self.label)?;
        enc.optional(self.version.as_ref())
    }
}

impl Decode for SearchRequest {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        let last = dec.optional()?;
        let label = dec.opaque_vector(LABEL)?.to_vec();
        let version = dec.optional()?;
        Ok(Self {
            last,
            label,
            version,
        })
    }
}

/// A contact-monitoring request (§13.2 `ContactMonitorRequest`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContactMonitorRequest {
    /// The tree size the user last observed.
    pub last: Option<u64>,
    /// The label being monitored.
    pub label: Vec<u8>,
    /// The versions being tracked and where they were last proven.
    pub entries: Vec<MonitorMapEntry>,
}

impl ContactMonitorRequest {
    /// `MonitorMapEntry entries<0..2^8-1>`.
    pub const ENTRIES: VectorSpec = VectorSpec::new((1 << 8) - 1);
}

impl Encode for ContactMonitorRequest {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.optional(self.last.as_ref())?;
        enc.opaque_vector(LABEL, &self.label)?;
        enc.vector(Self::ENTRIES, &self.entries)
    }
}

impl Decode for ContactMonitorRequest {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        let last = dec.optional()?;
        let label = dec.opaque_vector(LABEL)?.to_vec();
        let entries = dec.vector(Self::ENTRIES)?;
        Ok(Self {
            last,
            label,
            entries,
        })
    }
}

/// An owner-initialization request (§13.3 `OwnerInitRequest`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OwnerInitRequest {
    /// The tree size the user last observed.
    pub last: Option<u64>,
    /// The label being claimed.
    pub label: Vec<u8>,
    /// The distinguished log entry to start from.
    pub start: u64,
}

impl Encode for OwnerInitRequest {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.optional(self.last.as_ref())?;
        enc.opaque_vector(LABEL, &self.label)?;
        enc.u64(self.start);
        Ok(())
    }
}

impl Decode for OwnerInitRequest {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        let last = dec.optional()?;
        let label = dec.opaque_vector(LABEL)?.to_vec();
        let start = dec.u64()?;
        Ok(Self { last, label, start })
    }
}

/// An owner-monitoring request (§13.4 `OwnerMonitorRequest`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OwnerMonitorRequest {
    /// The tree size the user last observed.
    pub last: Option<u64>,
    /// The label being monitored.
    pub label: Vec<u8>,
    /// Versions not yet proven to be in a distinguished log entry.
    pub entries: Vec<MonitorMapEntry>,
    /// The rightmost distinguished log entry the owner has.
    pub start: u64,
    /// The greatest version the owner knows of.
    pub greatest_version: Option<u32>,
}

impl Encode for OwnerMonitorRequest {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.optional(self.last.as_ref())?;
        enc.opaque_vector(LABEL, &self.label)?;
        enc.vector(ContactMonitorRequest::ENTRIES, &self.entries)?;
        enc.u64(self.start);
        enc.optional(self.greatest_version.as_ref())
    }
}

impl Decode for OwnerMonitorRequest {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        let last = dec.optional()?;
        let label = dec.opaque_vector(LABEL)?.to_vec();
        let entries = dec.vector(ContactMonitorRequest::ENTRIES)?;
        let start = dec.u64()?;
        let greatest_version = dec.optional()?;
        Ok(Self {
            last,
            label,
            entries,
            start,
            greatest_version,
        })
    }
}

/// An update request (§13.5 `UpdateRequest`).
///
/// `values` may be empty, which §13.5 gives a specific meaning: the user is asking to
/// be told about versions above `greatest_version` rather than to create any.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpdateRequest {
    /// The tree size the user last observed.
    pub last: Option<u64>,
    /// The label being updated.
    pub label: Vec<u8>,
    /// The greatest version the user is aware of.
    pub greatest_version: Option<u32>,
    /// The values to publish; empty asks only to be informed.
    pub values: Vec<LabelValue>,
}

impl UpdateRequest {
    /// `LabelValue values<0..2^8-1>`.
    pub const VALUES: VectorSpec = VectorSpec::new((1 << 8) - 1);
}

impl Encode for UpdateRequest {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.optional(self.last.as_ref())?;
        enc.opaque_vector(LABEL, &self.label)?;
        enc.optional(self.greatest_version.as_ref())?;
        enc.vector(Self::VALUES, &self.values)
    }
}

impl Decode for UpdateRequest {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        let last = dec.optional()?;
        let label = dec.opaque_vector(LABEL)?.to_vec();
        let greatest_version = dec.optional()?;
        let values = dec.vector(Self::VALUES)?;
        Ok(Self {
            last,
            label,
            greatest_version,
            values,
        })
    }
}

/// An update request as forwarded to a Third-Party Manager (§14 `ManagerUpdateRequest`).
///
/// Under `thirdPartyManagement` a user's `UpdateRequest` goes to the Service Operator, which
/// checks access control and forwards it to the Manager with its own signature over each new
/// value attached. So this is an [`UpdateRequest`] with `values` promoted from [`LabelValue`] to
/// [`UpdateValue`] — the difference being the signature — plus `signed_version`.
///
/// `signed_version` exists because the signature covers a *version number* (§11.5's `UpdateTBS`),
/// and the Service Operator has to pick one before knowing what the Manager will assign. §14 says
/// it is "the version that was used in the computation of the Service Operator's signature over
/// the first element of `values`", zero when `values` is empty, and that a Manager seeing a
/// `signed_version` above the next version to be created MUST insert dummy entries — an all-zero
/// commitment per version — until the numbers line up. A `signed_version` *below* it "generally
/// indicates a bug in the Service Operator" and MUST be rejected.
///
/// # The field order here is the peer's, not the draft's
///
/// §14's presentation for this structure is corrupt: it opens with `UpdateRequest request;` and
/// then lists every field of an `UpdateRequest` again inline, so each one appears twice. Tracing
/// it upstream shows why — the structure was `{ UpdateRequest request; opaque signature<...>; }`
/// until a rework in July 2026 spelled the fields out and left the first member behind.
///
/// That makes the listing unusable as a wire format, and it is the *only* statement of the field
/// order: the prose says only that the structure "is the same as `UpdateRequest`" and "also
/// contains a `signed_version` field". The listing puts `signed_version` after `values`; the Go
/// peer, which implemented this two weeks before the rework landed, puts it before. Since the
/// listing cannot be right as written, there is nothing to prefer it on, and this follows the peer
/// so that the two interoperate. Recorded as `DRAFT-11`, filed as draft-protocol#50.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManagerUpdateRequest {
    /// The tree size the user last observed.
    pub last: Option<u64>,
    /// The label being updated.
    pub label: Vec<u8>,
    /// The greatest version the user is aware of.
    pub greatest_version: Option<u32>,
    /// The version the Service Operator's first signature was computed over, or zero.
    pub signed_version: u32,
    /// The values to publish, each with the Service Operator's signature.
    pub values: Vec<UpdateValue>,
}

impl ManagerUpdateRequest {
    /// `UpdateValue values<0..2^8-1>`.
    pub const VALUES: VectorSpec = VectorSpec::new((1 << 8) - 1);

    /// Reads a `ManagerUpdateRequest` under `mode`.
    ///
    /// The mode is needed for `values`: an [`UpdateValue`]'s suffix is present only under
    /// `thirdPartyManagement`, which is also the only mode where this structure exists at all.
    ///
    /// # Errors
    ///
    /// Codec errors from any member.
    pub fn decode_with_mode(
        dec: &mut Decoder<'_>,
        mode: crate::structs::DeploymentMode,
    ) -> Result<Self> {
        let last = dec.optional()?;
        let label = dec.opaque_vector(LABEL)?.to_vec();
        let greatest_version = dec.optional()?;
        let signed_version = dec.u32()?;
        let values =
            dec.vector_with(Self::VALUES, |dec| UpdateValue::decode_with_mode(dec, mode))?;
        Ok(Self {
            last,
            label,
            greatest_version,
            signed_version,
            values,
        })
    }
}

impl Encode for ManagerUpdateRequest {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.optional(self.last.as_ref())?;
        enc.opaque_vector(LABEL, &self.label)?;
        enc.optional(self.greatest_version.as_ref())?;
        enc.u32(self.signed_version);
        enc.vector(Self::VALUES, &self.values)
    }
}

/// The signed statement a Service Operator makes about an update (§11.5 `UpdateTBS`).
///
/// ```tls-presentation
/// struct {
///   Configuration config;
///   opaque label<0..2^8-1>;
///   uint32 version;
///   opaque value<0..2^32-1>;
/// } UpdateTBS;
/// ```
///
/// Only meaningful under `thirdPartyManagement`, where the Third-Party Manager runs
/// the tree and the Service Operator signs each modification. §11.5 requires users to
/// verify this signature *before consuming* `UpdateValue.value` — the value itself is
/// otherwise unauthenticated in that mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateTBS {
    /// The log's configuration.
    pub config: crate::heads::Configuration,
    /// The label being updated.
    pub label: Vec<u8>,
    /// The version being created.
    pub version: u32,
    /// The value, matching `UpdateValue.value`.
    pub value: Vec<u8>,
}

impl Encode for UpdateTBS {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        self.config.encode(enc)?;
        enc.opaque_vector(LABEL, &self.label)?;
        enc.u32(self.version);
        enc.opaque_vector(UpdateValue::VALUE, &self.value)
    }
}

impl Decode for UpdateTBS {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        let config = crate::heads::Configuration::decode(dec)?;
        let label = dec.opaque_vector(LABEL)?.to_vec();
        let version = dec.u32()?;
        let value = dec.opaque_vector(UpdateValue::VALUE)?.to_vec();
        Ok(Self {
            config,
            label,
            version,
            value,
        })
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
    use crate::codec::{Error, decode, encode};
    use crate::structs::DeploymentMode;
    use alloc::vec;

    #[test]
    fn search_requests_round_trip_both_ways() {
        // Greatest-version search: version absent (§6).
        let greatest = SearchRequest {
            last: Some(50),
            label: b"alice@example.com".to_vec(),
            version: None,
        };
        let bytes = encode(&greatest).unwrap();
        assert_eq!(bytes[0], 0x01, "last is present");
        assert_eq!(*bytes.last().unwrap(), 0x00, "version is absent");
        assert_eq!(decode::<SearchRequest>(&bytes).unwrap(), greatest);

        // Fixed-version search: version present (§7). One octet apart in meaning,
        // five bytes apart on the wire.
        let fixed = SearchRequest {
            version: Some(3),
            ..greatest.clone()
        };
        let fixed_bytes = encode(&fixed).unwrap();
        assert_eq!(fixed_bytes.len(), bytes.len() + 4);
        assert_eq!(decode::<SearchRequest>(&fixed_bytes).unwrap(), fixed);

        // A first-time user has no previous view.
        let fresh = SearchRequest {
            last: None,
            ..greatest
        };
        let fresh_bytes = encode(&fresh).unwrap();
        assert_eq!(fresh_bytes[0], 0x00);
        assert_eq!(fresh_bytes.len(), bytes.len() - 8);
        assert_eq!(decode::<SearchRequest>(&fresh_bytes).unwrap(), fresh);
    }

    /// §13.1: `proof` is `VRF.Np` bytes with no length prefix, so the decoder needs
    /// the suite's proof size. Reading it with the wrong size shifts the presence
    /// octet and changes the meaning of everything after.
    #[test]
    fn binary_ladder_steps_need_the_proof_size() {
        let with = BinaryLadderStep {
            proof: vec![0xaa; 80],
            commitment: Some(HashValue::from_bytes([0xbb; 32])),
        };
        let bytes = encode(&with).unwrap();
        assert_eq!(bytes.len(), 80 + 1 + 32);
        assert_eq!(bytes[80], 0x01, "the commitment is present");

        let mut dec = Decoder::new(&bytes);
        assert_eq!(
            BinaryLadderStep::decode_with_proof_size(&mut dec, 80).unwrap(),
            with
        );
        dec.finish().unwrap();

        // A step for a version that does not exist: a proof, and nothing to commit to.
        let without = BinaryLadderStep {
            proof: vec![0xaa; 80],
            commitment: None,
        };
        let bytes = encode(&without).unwrap();
        assert_eq!(bytes.len(), 81);
        assert_eq!(bytes[80], 0x00);
        let mut dec = Decoder::new(&bytes);
        assert_eq!(
            BinaryLadderStep::decode_with_proof_size(&mut dec, 80).unwrap(),
            without
        );

        // The P-256 suite's proofs are 81 bytes; reading an 80-byte one as 81 eats the
        // presence octet.
        let mut dec = Decoder::new(&bytes);
        assert!(BinaryLadderStep::decode_with_proof_size(&mut dec, 81).is_err());
    }

    #[test]
    fn monitor_map_entries_round_trip() {
        let entry = MonitorMapEntry {
            position: 0x0102_0304_0506_0708,
            version: 9,
        };
        let bytes = encode(&entry).unwrap();
        assert_eq!(bytes.len(), 12);
        assert_eq!(
            &bytes[..8],
            &[1, 2, 3, 4, 5, 6, 7, 8],
            "big-endian position"
        );
        assert_eq!(decode::<MonitorMapEntry>(&bytes).unwrap(), entry);
    }

    /// The `entries` vector counts elements, not bytes — §2.1.2 — so three 12-byte
    /// entries are a one-byte prefix of 3 and a 36-byte body.
    #[test]
    fn contact_monitor_requests_count_entries() {
        let request = ContactMonitorRequest {
            last: Some(10),
            label: b"bob".to_vec(),
            entries: vec![
                MonitorMapEntry {
                    position: 1,
                    version: 1,
                },
                MonitorMapEntry {
                    position: 5,
                    version: 2,
                },
                MonitorMapEntry {
                    position: 9,
                    version: 3,
                },
            ],
        };
        let bytes = encode(&request).unwrap();
        // 1 + 8 (last) + 1 + 3 (label) + 1 (count) + 36 (entries)
        assert_eq!(bytes.len(), 9 + 4 + 1 + 36);
        assert_eq!(bytes[13], 0x03, "the prefix counts entries, not bytes");
        assert_eq!(decode::<ContactMonitorRequest>(&bytes).unwrap(), request);
    }

    #[test]
    fn owner_requests_round_trip() {
        let init = OwnerInitRequest {
            last: None,
            label: b"carol".to_vec(),
            start: 0x1122_3344,
        };
        let bytes = encode(&init).unwrap();
        assert_eq!(decode::<OwnerInitRequest>(&bytes).unwrap(), init);

        let monitor = OwnerMonitorRequest {
            last: Some(64),
            label: b"carol".to_vec(),
            entries: vec![MonitorMapEntry {
                position: 7,
                version: 2,
            }],
            start: 31,
            greatest_version: Some(5),
        };
        let bytes = encode(&monitor).unwrap();
        assert_eq!(decode::<OwnerMonitorRequest>(&bytes).unwrap(), monitor);

        // The optional at the end is the difference between "I know of version 5" and
        // "I know of none".
        let unknown = OwnerMonitorRequest {
            greatest_version: None,
            ..monitor
        };
        let unknown_bytes = encode(&unknown).unwrap();
        assert_eq!(unknown_bytes.len(), bytes.len() - 4);
        assert_eq!(
            decode::<OwnerMonitorRequest>(&unknown_bytes).unwrap(),
            unknown
        );
    }

    /// §13.5 gives an empty `values` a meaning of its own: tell me about versions
    /// above `greatest_version`, do not create any. So it has to encode as an empty
    /// vector rather than be omitted.
    #[test]
    fn update_requests_distinguish_empty_from_absent() {
        let creating = UpdateRequest {
            last: Some(8),
            label: b"dave".to_vec(),
            greatest_version: Some(2),
            values: vec![
                LabelValue::new(b"key-1".to_vec()),
                LabelValue::new(b"key-2".to_vec()),
            ],
        };
        let bytes = encode(&creating).unwrap();
        assert_eq!(decode::<UpdateRequest>(&bytes).unwrap(), creating);

        let asking = UpdateRequest {
            values: Vec::new(),
            ..creating.clone()
        };
        let asking_bytes = encode(&asking).unwrap();
        assert_eq!(
            *asking_bytes.last().unwrap(),
            0x00,
            "an empty vector, not an omission"
        );
        assert_eq!(decode::<UpdateRequest>(&asking_bytes).unwrap(), asking);
        assert_ne!(asking_bytes, bytes);
    }

    #[test]
    fn label_values_round_trip() {
        let value = LabelValue::new(b"material".to_vec());
        let bytes = encode(&value).unwrap();
        assert_eq!(&bytes[..4], &[0, 0, 0, 8], "a four-byte length prefix");
        assert_eq!(decode::<LabelValue>(&bytes).unwrap(), value);
        assert_eq!(encode(&LabelValue::default()).unwrap(), vec![0, 0, 0, 0]);
    }

    /// `UpdateInfo` has two context-dependent parts: `Nc` from the suite and the
    /// suffix from the mode. Neither is discoverable from the bytes.
    #[test]
    fn update_info_needs_both_nc_and_the_mode() {
        let plain = UpdateInfo {
            opening: vec![0x11; 16],
            suffix: UpdateSuffix::Empty,
        };
        let bytes = encode(&plain).unwrap();
        assert_eq!(bytes.len(), 16);
        let mut dec = Decoder::new(&bytes);
        assert_eq!(
            UpdateInfo::decode_with(&mut dec, 16, DeploymentMode::ContactMonitoring).unwrap(),
            plain
        );
        dec.finish().unwrap();

        let managed = UpdateInfo {
            opening: vec![0x11; 16],
            suffix: UpdateSuffix::ThirdPartyManagement {
                signature: vec![0x22; 64],
            },
        };
        let bytes = encode(&managed).unwrap();
        assert_eq!(bytes.len(), 16 + 2 + 64);
        let mut dec = Decoder::new(&bytes);
        assert_eq!(
            UpdateInfo::decode_with(&mut dec, 16, DeploymentMode::ThirdPartyManagement).unwrap(),
            managed
        );
        dec.finish().unwrap();

        // Read in the wrong mode, the signature is left over rather than absorbed.
        let mut dec = Decoder::new(&bytes);
        let wrong =
            UpdateInfo::decode_with(&mut dec, 16, DeploymentMode::ContactMonitoring).unwrap();
        assert_eq!(wrong.suffix, UpdateSuffix::Empty);
        assert!(dec.finish().is_err());
    }

    /// §11.5's `UpdateTBS`: the configuration comes first, as in every other signed
    /// structure, so the same §11.2 question about `leaf_public_key` reaches it.
    #[test]
    fn update_tbs_starts_with_the_configuration() {
        let config = crate::heads::Configuration {
            cipher_suite: 2,
            mode: DeploymentMode::ThirdPartyManagement,
            signature_public_key: vec![0xaa; 32],
            vrf_public_key: vec![0xbb; 32],
            leaf_public_key: Some(vec![0xcc; 32]),
            auditor: None,
            max_ahead: 1,
            max_behind: 2,
            reasonable_monitoring_window: 3,
            maximum_lifetime: None,
        };
        let tbs = UpdateTBS {
            config: config.clone(),
            label: b"erin".to_vec(),
            version: 4,
            value: b"value".to_vec(),
        };
        let bytes = encode(&tbs).unwrap();
        let config_bytes = encode(&config).unwrap();
        assert_eq!(&bytes[..config_bytes.len()], &config_bytes[..]);
        assert_eq!(decode::<UpdateTBS>(&bytes).unwrap(), tbs);
    }

    #[test]
    fn oversized_labels_are_refused_everywhere() {
        let long = vec![0x61; 256];
        assert_eq!(
            encode(&SearchRequest {
                last: None,
                label: long.clone(),
                version: None
            }),
            Err(Error::VectorTooLong {
                count: 256,
                max: 255
            })
        );
        assert!(
            encode(&OwnerInitRequest {
                last: None,
                label: long.clone(),
                start: 0
            })
            .is_err()
        );
        assert!(
            encode(&UpdateRequest {
                last: None,
                label: long,
                greatest_version: None,
                values: Vec::new(),
            })
            .is_err()
        );
    }

    #[test]
    fn truncated_requests_are_rejected() {
        let request = SearchRequest {
            last: Some(1),
            label: b"x".to_vec(),
            version: Some(2),
        };
        let bytes = encode(&request).unwrap();
        for len in 0..bytes.len() {
            assert!(
                decode::<SearchRequest>(&bytes[..len]).is_err(),
                "a {len}-byte prefix decoded as a whole request"
            );
        }
    }

    /// A `ManagerUpdateRequest` round-trips, and its field order is the one recorded in the type's
    /// documentation: `signed_version` before `values`, which is the Go peer's order and not the
    /// (corrupt) listing in §14. Pinning it as bytes here is what makes the divergence visible if
    /// either side ever changes its mind.
    #[test]
    fn a_manager_update_request_round_trips() {
        let request = ManagerUpdateRequest {
            last: Some(7),
            label: b"alice".to_vec(),
            greatest_version: Some(3),
            signed_version: 4,
            values: vec![UpdateValue {
                value: vec![9, 9],
                suffix: UpdateSuffix::ThirdPartyManagement {
                    signature: vec![0xab; 64],
                },
            }],
        };
        let bytes = encode(&request).unwrap();
        let mut dec = Decoder::new(&bytes);
        assert_eq!(
            ManagerUpdateRequest::decode_with_mode(
                &mut dec,
                crate::structs::DeploymentMode::ThirdPartyManagement
            )
            .unwrap(),
            request
        );

        // The four bytes of `signed_version` sit immediately after `greatest_version`, which ends
        // the part this shares with an `UpdateRequest`. `last` is 1 + 8 bytes, the label 1 + 5,
        // `greatest_version` 1 + 4.
        let prefix = 1 + 8 + 1 + 5 + 1 + 4;
        assert_eq!(&bytes[prefix..prefix + 4], &[0, 0, 0, 4]);
        // And `values` follows it, with its own count.
        assert_eq!(bytes[prefix + 4], 1);
    }

    /// `signed_version` is zero when there is nothing signed, which §14 states as a rule rather
    /// than leaving to convention: an empty `values` field means the Service Operator signed
    /// nothing, so there is no version its signature could have covered.
    #[test]
    fn an_empty_manager_update_request_signs_version_zero() {
        let request = ManagerUpdateRequest {
            last: None,
            label: b"bob".to_vec(),
            greatest_version: None,
            signed_version: 0,
            values: Vec::new(),
        };
        let bytes = encode(&request).unwrap();
        let mut dec = Decoder::new(&bytes);
        assert_eq!(
            ManagerUpdateRequest::decode_with_mode(
                &mut dec,
                crate::structs::DeploymentMode::ThirdPartyManagement
            )
            .unwrap(),
            request
        );
        assert!(dec.is_empty());
    }
}
