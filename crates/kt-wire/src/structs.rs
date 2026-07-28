//! Protocol structs (`draft-ietf-keytrans-protocol-05` §11, §12, §13).
//!
//! Present so far: [`HashValue`] (§12.1), [`DeploymentMode`] (§11.2),
//! [`UpdateValue`] with its [`UpdateSuffix`] (§11.5), [`CommitmentValue`]
//! (§11.6), and [`LogEntry`] (§11.8). The proof types of §12 are in
//! [`crate::proofs`]. The rest arrive with the layers that consume them.

use alloc::vec::Vec;

use crate::codec::{Decode, Decoder, Encode, Encoder, Error, Result, VectorSpec};

/// A hash-function output: `opaque HashValue[Hash.Nh]` (§12.1).
///
/// Fixed at 32 bytes because `Hash.Nh` is 32 for both cipher suites in the §17.1
/// registry. A future suite with a different output length would need this type
/// parameterized; until one exists, a fixed-size array is what makes a
/// wrong-length hash unrepresentable rather than a runtime error.
///
/// [`HashValue::ZERO`] is not merely a default: §11.9 specifies an all-zero
/// string of length `Hash.Nh` as the stand-in for a prefix-tree child that does
/// not exist, and §12.2 uses the same value in a proof's `elements`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HashValue([u8; HashValue::SIZE]);

impl HashValue {
    /// `Hash.Nh` for both registered cipher suites.
    pub const SIZE: usize = 32;

    /// The all-zero hash: the stand-in for a missing prefix-tree child (§11.9).
    pub const ZERO: Self = Self([0; Self::SIZE]);

    /// Wraps exactly `Nh` bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self(bytes)
    }

    /// Wraps a slice that must be exactly `Nh` bytes.
    ///
    /// # Errors
    ///
    /// [`Error::HashLength`] if `bytes` is the wrong length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let array = <[u8; Self::SIZE]>::try_from(bytes).map_err(|_| Error::HashLength {
            expected: Self::SIZE,
            actual: bytes.len(),
        })?;
        Ok(Self(array))
    }

    /// The bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }

    /// Whether this is the all-zero stand-in value (§11.9).
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == Self::ZERO.0
    }
}

impl Encode for HashValue {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.opaque_fixed(&self.0);
        Ok(())
    }
}

impl Decode for HashValue {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        Self::from_slice(dec.opaque_fixed(Self::SIZE)?)
    }
}

/// How the Transparency Log is deployed (§11.2 `DeploymentMode`).
///
/// The mode is not carried in the structs that branch on it — it comes from
/// `Configuration`, which users learn out of band or from a tree head — so
/// decoding any struct with a `select (Configuration.mode)` takes it as an
/// argument.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum DeploymentMode {
    /// `contactMonitoring(1)`: users monitor the labels of their contacts.
    ContactMonitoring,
    /// `thirdPartyManagement(2)`: a Third-Party Manager operates the tree and
    /// the Service Operator signs each update.
    ThirdPartyManagement,
    /// `thirdPartyAuditing(3)`: a Third-Party Auditor countersigns tree heads.
    ThirdPartyAuditing,
}

impl DeploymentMode {
    /// The registry value from §11.2.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::ContactMonitoring => 1,
            Self::ThirdPartyManagement => 2,
            Self::ThirdPartyAuditing => 3,
        }
    }

    /// Parses a registry value.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEnum`] for anything outside the registry, including
    /// `reserved(0)`.
    pub const fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::ContactMonitoring),
            2 => Ok(Self::ThirdPartyManagement),
            3 => Ok(Self::ThirdPartyAuditing),
            other => Err(Error::InvalidEnum {
                name: "DeploymentMode",
                value: other as u64,
            }),
        }
    }

    /// Whether this mode carries a Service Operator signature in
    /// `UpdateSuffix` (§11.5).
    #[must_use]
    pub const fn has_update_signature(self) -> bool {
        matches!(self, Self::ThirdPartyManagement)
    }
}

impl Encode for DeploymentMode {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.u8(self.as_u8());
        Ok(())
    }
}

impl Decode for DeploymentMode {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        Self::from_u8(dec.u8()?)
    }
}

/// The mode-dependent tail of an `UpdateValue` (§11.5 `UpdateSuffix`).
///
/// ```tls-presentation
/// struct {
///   select (Configuration.mode) {
///     case thirdPartyManagement:
///       opaque signature<0..2^16-1>;
///   };
/// } UpdateSuffix;
/// ```
///
/// Only `thirdPartyManagement` has a case, so in the other two modes the suffix
/// contributes no bytes at all.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum UpdateSuffix {
    /// No bytes: `contactMonitoring` or `thirdPartyAuditing`.
    #[default]
    Empty,
    /// A Service Operator signature over `UpdateTBS`, under
    /// `thirdPartyManagement`.
    ThirdPartyManagement {
        /// `opaque signature<0..2^16-1>`.
        signature: Vec<u8>,
    },
}

impl UpdateSuffix {
    /// `opaque signature<0..2^16-1>`.
    pub const SIGNATURE: VectorSpec = VectorSpec::new((1 << 16) - 1);

    /// The mode this suffix belongs to, or `None` if it is mode-agnostic.
    ///
    /// [`UpdateSuffix::Empty`] is correct for two of the three modes, so it maps
    /// to `None` rather than picking one.
    #[must_use]
    pub const fn mode(&self) -> Option<DeploymentMode> {
        match self {
            Self::Empty => None,
            Self::ThirdPartyManagement { .. } => Some(DeploymentMode::ThirdPartyManagement),
        }
    }

    /// Reads the suffix that `mode` implies.
    ///
    /// # Errors
    ///
    /// Codec errors from the signature vector under `thirdPartyManagement`.
    pub fn decode_with_mode(dec: &mut Decoder<'_>, mode: DeploymentMode) -> Result<Self> {
        if mode.has_update_signature() {
            let signature = dec.opaque_vector(Self::SIGNATURE)?;
            Ok(Self::ThirdPartyManagement {
                signature: signature.to_vec(),
            })
        } else {
            Ok(Self::Empty)
        }
    }
}

impl Encode for UpdateSuffix {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        match self {
            Self::Empty => Ok(()),
            Self::ThirdPartyManagement { signature } => {
                enc.opaque_vector(Self::SIGNATURE, signature)
            }
        }
    }
}

/// The contents of a prefix-tree commitment (§11.5 `UpdateValue`).
///
/// ```tls-presentation
/// struct {
///   opaque value<0..2^32-1>;
///   UpdateSuffix suffix;
/// } UpdateValue;
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpdateValue {
    /// The value bound to a label-version pair, e.g. a public key.
    pub value: Vec<u8>,
    /// Mode-dependent tail; see [`UpdateSuffix`].
    pub suffix: UpdateSuffix,
}

impl UpdateValue {
    /// `opaque value<0..2^32-1>`.
    pub const VALUE: VectorSpec = VectorSpec::new((1 << 32) - 1);

    /// An update with no suffix, i.e. any mode but `thirdPartyManagement`.
    #[must_use]
    pub fn new(value: impl Into<Vec<u8>>) -> Self {
        Self {
            value: value.into(),
            suffix: UpdateSuffix::Empty,
        }
    }

    /// Reads an `UpdateValue` as `mode` defines it.
    ///
    /// # Errors
    ///
    /// Codec errors from the value vector or the suffix.
    pub fn decode_with_mode(dec: &mut Decoder<'_>, mode: DeploymentMode) -> Result<Self> {
        let value = dec.opaque_vector(Self::VALUE)?;
        let suffix = UpdateSuffix::decode_with_mode(dec, mode)?;
        Ok(Self {
            value: value.to_vec(),
            suffix,
        })
    }
}

impl Encode for UpdateValue {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.opaque_vector(Self::VALUE, &self.value)?;
        self.suffix.encode(enc)
    }
}

/// The preimage of a commitment (§11.6 `CommitmentValue`).
///
/// ```tls-presentation
/// struct {
///   opaque opening[Nc];
///   opaque label<0..2^8-1>;
///   uint32 version;
///   UpdateValue update;
/// } CommitmentValue;
/// ```
///
/// `Nc` comes from the cipher suite (16 for both suites registered in §17.1),
/// which is why `opening` is a `Vec<u8>` and not a fixed-size array: this crate
/// deliberately depends on nothing, including the suite definitions. Encoding
/// writes `opening` unprefixed, exactly as long as the caller made it;
/// [`CommitmentValue::decode_with_nc`] is where `Nc` is applied.
///
/// The commitment itself — `HMAC(Kc, CommitmentValue)` — lives in `kt-crypto`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommitmentValue {
    /// The `Nc`-byte opening. Randomly generated, or derived so as to be
    /// indistinguishable from random (§11.6).
    pub opening: Vec<u8>,
    /// The label being committed to, e.g. a username.
    pub label: Vec<u8>,
    /// The version of the label.
    pub version: u32,
    /// The value the commitment opens to.
    pub update: UpdateValue,
}

impl CommitmentValue {
    /// `opaque label<0..2^8-1>`.
    pub const LABEL: VectorSpec = VectorSpec::new((1 << 8) - 1);

    /// Reads a `CommitmentValue` whose opening is `nc` bytes under `mode`.
    ///
    /// # Errors
    ///
    /// Codec errors, including [`Error::UnexpectedEof`] if fewer than `nc` bytes
    /// are available for the opening.
    pub fn decode_with_nc(dec: &mut Decoder<'_>, nc: usize, mode: DeploymentMode) -> Result<Self> {
        let opening = dec.opaque_fixed(nc)?;
        let label = dec.opaque_vector(Self::LABEL)?;
        let version = dec.u32()?;
        let update = UpdateValue::decode_with_mode(dec, mode)?;
        Ok(Self {
            opening: opening.to_vec(),
            label: label.to_vec(),
            version,
            update,
        })
    }
}

impl Encode for CommitmentValue {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.opaque_fixed(&self.opening);
        enc.opaque_vector(Self::LABEL, &self.label)?;
        enc.u32(self.version);
        self.update.encode(enc)
    }
}

/// The VRF's input for a label-version pair (§11.7 `VrfInput`).
///
/// ```tls-presentation
/// struct {
///   opaque label<0..2^8-1>;
///   uint32 version;
/// } VrfInput;
/// ```
///
/// The VRF output over this structure is the label-version pair's search key in
/// the prefix tree, which is what keeps labels private: the tree is indexed by
/// something only the log can compute, and a user who is shown a search key learns
/// nothing about the label unless they already know it.
///
/// The encoding is the whole point of the type. `label` carries a length prefix, so
/// `("ab", 1)` and `("a", …)` cannot collide the way a bare concatenation would.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VrfInput {
    /// The label, e.g. a username.
    pub label: Vec<u8>,
    /// The version of that label.
    pub version: u32,
}

impl VrfInput {
    /// `opaque label<0..2^8-1>`.
    pub const LABEL: VectorSpec = VectorSpec::new((1 << 8) - 1);

    /// A `VrfInput` for `label` at `version`.
    #[must_use]
    pub fn new(label: impl Into<Vec<u8>>, version: u32) -> Self {
        Self {
            label: label.into(),
            version,
        }
    }
}

impl Encode for VrfInput {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.opaque_vector(Self::LABEL, &self.label)?;
        enc.u32(self.version);
        Ok(())
    }
}

impl Decode for VrfInput {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        let label = dec.opaque_vector(Self::LABEL)?;
        let version = dec.u32()?;
        Ok(Self {
            label: label.to_vec(),
            version,
        })
    }
}

/// A leaf of the log tree (§11.8 `LogEntry`).
///
/// ```tls-presentation
/// struct {
///   uint64 timestamp;
///   opaque prefix_tree[Hash.Nh];
/// } LogEntry;
/// ```
///
/// The leaf's value in the log tree is the hash of this structure — see
/// `kt_tree::log`. `timestamp` is milliseconds since the Unix epoch, and it is
/// what the implicit binary search tree's monotonicity checks are about (§4.1);
/// `prefix_tree` is the prefix-tree root after the entry's modifications.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct LogEntry {
    /// Milliseconds since the Unix epoch.
    pub timestamp: u64,
    /// The prefix tree root as of this entry.
    pub prefix_tree: HashValue,
}

impl Encode for LogEntry {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.u64(self.timestamp);
        self.prefix_tree.encode(enc)
    }
}

impl Decode for LogEntry {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        let timestamp = dec.u64()?;
        let prefix_tree = HashValue::decode(dec)?;
        Ok(Self {
            timestamp,
            prefix_tree,
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
    use crate::codec::{Decoder, encode};
    use alloc::vec;

    /// The first vector in `interop/vectors/commitment.json`, hand-checked
    /// against §11.6 field by field: 16 bytes of opening, a zero-length label,
    /// version 0, then an `UpdateValue` whose only content is a zero-length
    /// `value` vector with a four-byte prefix.
    #[test]
    fn empty_label_empty_value_layout() {
        let cv = CommitmentValue {
            opening: (0..16).collect(),
            label: Vec::new(),
            version: 0,
            update: UpdateValue::new(Vec::new()),
        };
        let bytes = encode(&cv).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, // opening[16]
                0x00, // label<0..255>, empty
                0x00, 0x00, 0x00, 0x00, // version
                0x00, 0x00, 0x00, 0x00, // update.value<0..2^32-1>, empty
            ]
        );
        assert_eq!(bytes.len(), 16 + 1 + 4 + 4);
    }

    #[test]
    fn commitment_value_round_trips() {
        let cv = CommitmentValue {
            opening: (0x10..0x20).collect(),
            label: b"alice@example.com".to_vec(),
            version: 1,
            update: UpdateValue::new(b"key-material-2".to_vec()),
        };
        let bytes = encode(&cv).unwrap();
        let mut dec = Decoder::new(&bytes);
        let back = CommitmentValue::decode_with_nc(&mut dec, 16, DeploymentMode::ContactMonitoring)
            .unwrap();
        dec.finish().unwrap();
        assert_eq!(back, cv);
    }

    /// Under third-party management the suffix carries a signature, so the same
    /// logical update encodes to different bytes. Getting the mode wrong is a
    /// commitment mismatch, not a silent success.
    #[test]
    fn third_party_management_suffix_changes_the_bytes() {
        let mut cv = CommitmentValue {
            opening: vec![0_u8; 16],
            label: b"bob".to_vec(),
            version: 2,
            update: UpdateValue {
                value: b"v".to_vec(),
                suffix: UpdateSuffix::ThirdPartyManagement {
                    signature: vec![0xaa, 0xbb],
                },
            },
        };
        let bytes = encode(&cv).unwrap();
        assert_eq!(bytes.last(), Some(&0xbb));

        let mut dec = Decoder::new(&bytes);
        let back =
            CommitmentValue::decode_with_nc(&mut dec, 16, DeploymentMode::ThirdPartyManagement)
                .unwrap();
        dec.finish().unwrap();
        assert_eq!(back, cv);

        // Decoded in the wrong mode, the signature's own length prefix is left
        // over as trailing bytes rather than being silently absorbed.
        let mut dec = Decoder::new(&bytes);
        let wrong_mode =
            CommitmentValue::decode_with_nc(&mut dec, 16, DeploymentMode::ContactMonitoring)
                .unwrap();
        assert_eq!(wrong_mode.update.suffix, UpdateSuffix::Empty);
        assert!(dec.finish().is_err());

        cv.update.suffix = UpdateSuffix::Empty;
        assert_ne!(encode(&cv).unwrap(), bytes);
    }

    /// A 256-byte label cannot be expressed: the ceiling is `2^8-1` (§11.6).
    #[test]
    fn over_long_label_is_rejected() {
        let cv = CommitmentValue {
            opening: vec![0_u8; 16],
            label: vec![0x61; 256],
            version: 0,
            update: UpdateValue::new(Vec::new()),
        };
        assert_eq!(
            encode(&cv),
            Err(Error::VectorTooLong {
                count: 256,
                max: 255
            })
        );
    }

    #[test]
    fn deployment_mode_rejects_reserved_and_unknown() {
        assert_eq!(
            DeploymentMode::from_u8(1),
            Ok(DeploymentMode::ContactMonitoring)
        );
        assert_eq!(
            DeploymentMode::from_u8(2),
            Ok(DeploymentMode::ThirdPartyManagement)
        );
        assert_eq!(
            DeploymentMode::from_u8(3),
            Ok(DeploymentMode::ThirdPartyAuditing)
        );
        for value in [0_u8, 4, 255] {
            assert_eq!(
                DeploymentMode::from_u8(value),
                Err(Error::InvalidEnum {
                    name: "DeploymentMode",
                    value: u64::from(value)
                })
            );
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "tests fail loudly by panicking; the lints protect the parsing paths"
)]
mod more_tests {
    use super::*;
    use crate::codec::{decode, encode};
    use alloc::vec;

    /// `HashValue`'s constructors and the stand-in value §11.9 depends on.
    #[test]
    fn hash_values_round_trip_and_report_zero() {
        let bytes = [0x5a_u8; HashValue::SIZE];
        let value = HashValue::from_bytes(bytes);
        assert_eq!(value.as_bytes(), &bytes);
        assert!(!value.is_zero());
        assert!(HashValue::ZERO.is_zero());
        assert!(
            HashValue::default().is_zero(),
            "the default is the §11.9 stand-in"
        );

        assert_eq!(HashValue::from_slice(&bytes), Ok(value));
        assert_eq!(
            HashValue::from_slice(&bytes[..31]),
            Err(Error::HashLength {
                expected: 32,
                actual: 31
            })
        );
        assert_eq!(
            HashValue::from_slice(&[0; 33]),
            Err(Error::HashLength {
                expected: 32,
                actual: 33
            })
        );

        // On the wire it is a fixed-size opaque: no length prefix.
        assert_eq!(encode(&value).unwrap(), bytes.to_vec());
        assert_eq!(decode::<HashValue>(&bytes).unwrap(), value);
        assert!(decode::<HashValue>(&bytes[..31]).is_err());
    }

    /// §11.8's leaf, whose encoding the log tree hashes. Nothing had decoded one
    /// before: a log verifier only ever hashes them, but a server reading its own
    /// storage needs the other direction.
    #[test]
    fn log_entries_round_trip() {
        let entry = LogEntry {
            timestamp: 0x0102_0304_0506_0708,
            prefix_tree: HashValue::from_bytes([0xab; 32]),
        };
        let bytes = encode(&entry).unwrap();
        assert_eq!(bytes.len(), 8 + 32, "uint64 then opaque[Nh]");
        assert_eq!(
            &bytes[..8],
            &[1, 2, 3, 4, 5, 6, 7, 8],
            "big-endian timestamp"
        );
        assert_eq!(decode::<LogEntry>(&bytes).unwrap(), entry);

        assert_eq!(LogEntry::default().timestamp, 0);
        assert!(decode::<LogEntry>(&bytes[..39]).is_err());
    }

    /// §11.7's VRF input. The length prefix on `label` is the whole reason this is a
    /// struct and not a concatenation, so the test pins the layout byte by byte.
    #[test]
    fn vrf_inputs_round_trip_and_prefix_their_label() {
        let input = VrfInput::new(b"ab".to_vec(), 0x0000_0001);
        let bytes = encode(&input).unwrap();
        assert_eq!(bytes, vec![0x02, b'a', b'b', 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(decode::<VrfInput>(&bytes).unwrap(), input);

        // ("a", 0x62000000) and ("ab", 0) share their bytes after the prefix; the
        // prefix is what keeps them apart.
        let one = encode(&VrfInput::new(b"a".to_vec(), 0x6200_0000)).unwrap();
        let two = encode(&VrfInput::new(b"ab".to_vec(), 0)).unwrap();
        assert_ne!(one, two);

        assert_eq!(VrfInput::default(), VrfInput::new(Vec::new(), 0));
        assert_eq!(
            encode(&VrfInput::new(vec![0x61; 256], 0)),
            Err(Error::VectorTooLong {
                count: 256,
                max: 255
            }),
            "§11.7's label ceiling is 2^8-1"
        );
        assert!(decode::<VrfInput>(&[0x02, b'a']).is_err());
    }

    /// The mode an `UpdateSuffix` belongs to, which callers use to check a suffix
    /// against the `Configuration` they are verifying under.
    #[test]
    fn update_suffix_reports_its_mode() {
        assert_eq!(
            UpdateSuffix::Empty.mode(),
            None,
            "empty fits two of the three modes"
        );
        assert_eq!(
            UpdateSuffix::ThirdPartyManagement {
                signature: vec![1, 2]
            }
            .mode(),
            Some(DeploymentMode::ThirdPartyManagement)
        );
        assert_eq!(UpdateSuffix::default(), UpdateSuffix::Empty);
    }

    #[test]
    fn deployment_modes_round_trip_on_the_wire() {
        for mode in [
            DeploymentMode::ContactMonitoring,
            DeploymentMode::ThirdPartyManagement,
            DeploymentMode::ThirdPartyAuditing,
        ] {
            let bytes = encode(&mode).unwrap();
            assert_eq!(bytes, vec![mode.as_u8()]);
            assert_eq!(decode::<DeploymentMode>(&bytes).unwrap(), mode);
            assert_eq!(
                mode.has_update_signature(),
                mode == DeploymentMode::ThirdPartyManagement,
                "only third-party management signs updates (§11.5)"
            );
        }
        assert!(decode::<DeploymentMode>(&[0]).is_err(), "reserved(0)");
    }

    /// `UpdateValue::new` and the ceiling on its value.
    #[test]
    fn update_values_are_built_and_bounded() {
        let update = UpdateValue::new(b"key".to_vec());
        assert_eq!(update.suffix, UpdateSuffix::Empty);
        assert_eq!(update.value, b"key");
        assert_eq!(UpdateValue::default().value, Vec::<u8>::new());

        // The 2^32-1 ceiling is not reachable in a test, but the spec constant is,
        // and it is what the encoder checks against.
        assert_eq!(UpdateValue::VALUE.max_count(), (1 << 32) - 1);
        assert_eq!(CommitmentValue::LABEL.max_count(), 255);
        assert_eq!(UpdateSuffix::SIGNATURE.max_count(), 65_535);
        assert_eq!(VrfInput::LABEL.max_count(), 255);
    }

    /// A commitment value whose opening is the wrong length still encodes — `Nc`
    /// belongs to the cipher suite, which this crate does not know — so the check
    /// lives in `kt-crypto`. Decoding is where `Nc` is applied.
    #[test]
    fn commitment_value_decoding_applies_nc() {
        let cv = CommitmentValue {
            opening: vec![0xaa; 16],
            label: b"x".to_vec(),
            version: 1,
            update: UpdateValue::new(b"v".to_vec()),
        };
        let bytes = encode(&cv).unwrap();

        let mut dec = Decoder::new(&bytes);
        let decoded =
            CommitmentValue::decode_with_nc(&mut dec, 16, DeploymentMode::ContactMonitoring)
                .unwrap();
        assert_eq!(decoded, cv);
        dec.finish().unwrap();

        // Reading it with the wrong Nc shifts every following field, so the label
        // length is read out of the middle of the opening and the parse fails or
        // produces something else — either way it must not silently succeed as `cv`.
        let mut dec = Decoder::new(&bytes);
        let other = CommitmentValue::decode_with_nc(&mut dec, 8, DeploymentMode::ContactMonitoring);
        assert!(other.is_err() || other.unwrap() != cv);
    }
}
