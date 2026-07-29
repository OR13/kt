//! What a log sends back (§13).
//!
//! Responses are the first structures whose shape depends on the *request*, not just on the
//! configuration. A `SearchResponse` carries a `version` field only when the request left
//! `version` absent — the log is answering "the greatest one, and here is which" — so a
//! decoder that does not know what was asked cannot read the bytes. That is why every
//! decoder here takes its context explicitly rather than guessing.
//!
//! The `CombinedTreeProof` inside is worse in the same way: its elements are ordered by
//! whichever algorithm the user is running, and nothing in the bytes says which. Decoding it
//! yields vectors of the right shape; knowing what each element *is* takes the algorithm.
//! See [`crate::proofs::CombinedTreeProof`].

use alloc::vec::Vec;

use crate::codec::{Decode, Decoder, Encode, Encoder, Result, VectorSpec};
use crate::heads::FullTreeHead;
use crate::proofs::CombinedTreeProof;
use crate::requests::BinaryLadderStep;
use crate::structs::{DeploymentMode, UpdateValue};

/// The log's answer to a `SearchRequest` (§13.1).
///
/// ```text
/// struct {
///   FullTreeHead full_tree_head;
///
///   select (SearchRequest.version) {
///     case absent:
///       uint32 version;
///   };
///   opaque opening[Nc];
///   UpdateValue value;
///
///   BinaryLadderStep binary_ladder<0..2^8-1>;
///   CombinedTreeProof search;
/// } SearchResponse;
/// ```
///
/// `version` is present exactly when the request did not name one: a greatest-version search
/// has to be told which version it found. `opening` and `value` are the target version's, and
/// together they reproduce its commitment — which is why §13.1 step 2 requires that
/// `binary_ladder` carry *no* commitment for the target version. `binary_ladder` runs in the
/// order §5 outputs the versions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchResponse {
    /// The tree head, and the auditor's where the mode has one.
    pub full_tree_head: FullTreeHead,
    /// The greatest version, present only when the request left `version` absent.
    pub version: Option<u32>,
    /// The target version's commitment opening, `Nc` bytes.
    pub opening: Vec<u8>,
    /// The target version's value.
    pub value: UpdateValue,
    /// One step per version in the target's binary ladder (§5).
    pub binary_ladder: Vec<BinaryLadderStep>,
    /// Everything the search and the view update needed from the log entries inspected.
    pub search: CombinedTreeProof,
}

impl SearchResponse {
    /// `BinaryLadderStep binary_ladder<0..2^8-1>`.
    pub const LADDER: VectorSpec = VectorSpec::new((1 << 8) - 1);

    /// Reads a `SearchResponse` for a request that asked for `version`.
    ///
    /// `mode` selects whether the `FullTreeHead` carries an auditor head (§11.4), `nc` is the
    /// cipher suite's commitment opening size, `proof_size` is `VRF.Np`, and
    /// `version_requested` says whether the request named a version — which is what decides
    /// whether a `version` field is on the wire at all.
    ///
    /// # Errors
    ///
    /// Codec errors from any member. A response read with the wrong context will usually
    /// fail here rather than silently decode, because the `CombinedTreeProof`'s length
    /// prefixes end up being read from the middle of something else — but "usually" is not
    /// "always", which is why the context is a parameter and not a guess.
    pub fn decode_with(
        dec: &mut Decoder<'_>,
        mode: DeploymentMode,
        nc: usize,
        proof_size: usize,
        version_requested: bool,
    ) -> Result<Self> {
        let full_tree_head = FullTreeHead::decode_with_mode(dec, mode)?;
        let version = if version_requested {
            None
        } else {
            Some(u32::decode(dec)?)
        };
        let opening = dec.opaque_fixed(nc)?.to_vec();
        let value = UpdateValue::decode_with_mode(dec, mode)?;
        // `binary_ladder`'s elements are not self-delimiting — a step's proof is `VRF.Np`
        // bytes with no prefix of its own — so the count is read here and the steps are
        // decoded with the suite's proof size.
        let binary_ladder = dec.vector_with(Self::LADDER, |dec| {
            BinaryLadderStep::decode_with_proof_size(dec, proof_size)
        })?;
        let search = CombinedTreeProof::decode(dec)?;
        Ok(Self {
            full_tree_head,
            version,
            opening,
            value,
            binary_ladder,
            search,
        })
    }
}

impl Encode for SearchResponse {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        self.full_tree_head.encode(enc)?;
        if let Some(version) = self.version {
            version.encode(enc)?;
        }
        enc.opaque_fixed(&self.opening);
        self.value.encode(enc)?;
        enc.vector(Self::LADDER, &self.binary_ladder)?;
        self.search.encode(enc)
    }
}

/// The log's answer to a `ContactMonitorRequest` (§13.2).
///
/// ```text
/// struct {
///   FullTreeHead full_tree_head;
///   CombinedTreeProof monitor;
/// } ContactMonitorResponse;
/// ```
///
/// Two fields and no ladder, which is the whole difference between monitoring and searching: a
/// searcher is asking *what* the value is, and needs commitments and openings to find out, while
/// a monitor already knows and is asking only whether the log has kept it where it was. So
/// everything the response carries is in the proof, and §12.3.4 decides the order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactMonitorResponse {
    /// The tree head, and the auditor's where the mode has one.
    pub full_tree_head: FullTreeHead,
    /// The monitoring proof: the view update, then §8.2's algorithm.
    pub monitor: CombinedTreeProof,
}

impl ContactMonitorResponse {
    /// Reads a `ContactMonitorResponse` under `mode`.
    ///
    /// # Errors
    ///
    /// Codec errors from either member.
    pub fn decode_with(dec: &mut Decoder<'_>, mode: DeploymentMode) -> Result<Self> {
        let full_tree_head = FullTreeHead::decode_with_mode(dec, mode)?;
        let monitor = CombinedTreeProof::decode(dec)?;
        Ok(Self {
            full_tree_head,
            monitor,
        })
    }
}

impl Encode for ContactMonitorResponse {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        self.full_tree_head.encode(enc)?;
        self.monitor.encode(enc)
    }
}

/// The log's answer to an `OwnerMonitorRequest` (§13.4).
///
/// Structurally identical to [`ContactMonitorResponse`], and deliberately not the same type:
/// the proofs inside are ordered by different algorithms — §8.2's alone for a contact, §8.2's
/// followed by §8.3's second algorithm for an owner — and the bytes do not say which. A single
/// type would invite reading one as the other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerMonitorResponse {
    /// The tree head, and the auditor's where the mode has one.
    pub full_tree_head: FullTreeHead,
    /// The monitoring proof: the view update, then §8.2's algorithm, then §8.3's second.
    pub monitor: CombinedTreeProof,
}

impl OwnerMonitorResponse {
    /// Reads an `OwnerMonitorResponse` under `mode`.
    ///
    /// # Errors
    ///
    /// Codec errors from either member.
    pub fn decode_with(dec: &mut Decoder<'_>, mode: DeploymentMode) -> Result<Self> {
        let full_tree_head = FullTreeHead::decode_with_mode(dec, mode)?;
        let monitor = CombinedTreeProof::decode(dec)?;
        Ok(Self {
            full_tree_head,
            monitor,
        })
    }
}

impl Encode for OwnerMonitorResponse {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        self.full_tree_head.encode(enc)?;
        self.monitor.encode(enc)
    }
}

/// The log's answer to an `OwnerInitRequest` (§13.3).
///
/// ```text
/// struct {
///   FullTreeHead full_tree_head;
///
///   uint32 greatest_versions<0..2^8-1>;
///   BinaryLadderStep binary_ladder<0..2^16-1>;
///   CombinedTreeProof init;
/// } OwnerInitResponse;
/// ```
///
/// `greatest_versions` is the greatest version present at each entry §8.3's first algorithm
/// inspects, "ending at the first log entry where the label doesn't exist" — so it may be
/// shorter than that list, and §13.3 step 1 requires it to be descending. `binary_ladder` is one
/// step per version that algorithm looks up, ascending by version, with a commitment for each
/// version that exists — and §13.3 goes out of its way to note that "the existence of a version
/// does not require the existence of all lesser versions", so the commitments are not a prefix.
///
/// Note the wider bound on `binary_ladder` here than in a `SearchResponse`: `<0..2^16-1>` rather
/// than `<0..2^8-1>`. An owner initializing state may be catching up over many entries at once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerInitResponse {
    /// The tree head, and the auditor's where the mode has one.
    pub full_tree_head: FullTreeHead,
    /// The greatest version at each inspected entry, descending.
    pub greatest_versions: Vec<u32>,
    /// One step per version looked up, ascending by version.
    pub binary_ladder: Vec<BinaryLadderStep>,
    /// The proof: the view update, then §8.3's first algorithm.
    pub init: CombinedTreeProof,
}

impl OwnerInitResponse {
    /// `uint32 greatest_versions<0..2^8-1>`.
    pub const VERSIONS: VectorSpec = VectorSpec::new((1 << 8) - 1);
    /// `BinaryLadderStep binary_ladder<0..2^16-1>`.
    pub const LADDER: VectorSpec = VectorSpec::new((1 << 16) - 1);

    /// Reads an `OwnerInitResponse` under `mode`, with `VRF.Np`-byte ladder proofs.
    ///
    /// # Errors
    ///
    /// Codec errors from any member.
    pub fn decode_with(
        dec: &mut Decoder<'_>,
        mode: DeploymentMode,
        proof_size: usize,
    ) -> Result<Self> {
        let full_tree_head = FullTreeHead::decode_with_mode(dec, mode)?;
        let greatest_versions = dec.vector(Self::VERSIONS)?;
        let binary_ladder = dec.vector_with(Self::LADDER, |dec| {
            BinaryLadderStep::decode_with_proof_size(dec, proof_size)
        })?;
        let init = CombinedTreeProof::decode(dec)?;
        Ok(Self {
            full_tree_head,
            greatest_versions,
            binary_ladder,
            init,
        })
    }
}

impl Encode for OwnerInitResponse {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        self.full_tree_head.encode(enc)?;
        enc.vector(Self::VERSIONS, &self.greatest_versions)?;
        enc.vector(Self::LADDER, &self.binary_ladder)?;
        self.init.encode(enc)
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests fail loudly by panicking; the lints protect the parsing paths"
)]
mod tests {
    use super::*;
    use crate::codec::encode;
    use crate::heads::TreeHead;
    use crate::proofs::{InclusionProof, PrefixProof, PrefixSearchResult};
    use crate::structs::{HashValue, UpdateSuffix};
    use alloc::vec;

    fn response(version: Option<u32>) -> SearchResponse {
        SearchResponse {
            full_tree_head: FullTreeHead::Updated {
                tree_head: TreeHead {
                    tree_size: 9,
                    signature: vec![7; 64],
                },
                auditor_tree_head: None,
            },
            version,
            opening: vec![0xab; 16],
            value: UpdateValue {
                value: vec![1, 2, 3],
                suffix: UpdateSuffix::Empty,
            },
            binary_ladder: vec![
                BinaryLadderStep {
                    proof: vec![0x11; 80],
                    commitment: Some(HashValue::from_bytes([0x22; 32])),
                },
                BinaryLadderStep {
                    proof: vec![0x33; 80],
                    commitment: None,
                },
            ],
            search: CombinedTreeProof {
                timestamps: vec![1, 2, 3],
                prefix_proofs: vec![PrefixProof {
                    results: vec![PrefixSearchResult::Inclusion { depth: 4 }],
                    elements: vec![HashValue::from_bytes([0x44; 32])],
                }],
                prefix_roots: vec![HashValue::from_bytes([0x55; 32])],
                inclusion: InclusionProof::new(vec![HashValue::from_bytes([0x66; 32])]),
            },
        }
    }

    #[test]
    fn round_trips_for_a_greatest_version_search() {
        let value = response(Some(4));
        let bytes = encode(&value).unwrap();
        let mut dec = Decoder::new(&bytes);
        let decoded =
            SearchResponse::decode_with(&mut dec, DeploymentMode::ContactMonitoring, 16, 80, false)
                .unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn round_trips_for_a_fixed_version_search() {
        let value = response(None);
        let bytes = encode(&value).unwrap();
        let mut dec = Decoder::new(&bytes);
        let decoded =
            SearchResponse::decode_with(&mut dec, DeploymentMode::ContactMonitoring, 16, 80, true)
                .unwrap();
        assert_eq!(decoded, value);
    }

    /// The two monitoring responses round-trip, and the owner's carries its two extra vectors.
    #[test]
    fn monitoring_responses_round_trip() {
        let proof = CombinedTreeProof {
            timestamps: vec![7, 8],
            prefix_proofs: vec![PrefixProof {
                results: vec![PrefixSearchResult::Inclusion { depth: 2 }],
                elements: vec![HashValue::from_bytes([0x11; 32])],
            }],
            prefix_roots: vec![HashValue::from_bytes([0x22; 32])],
            inclusion: InclusionProof::new(vec![HashValue::from_bytes([0x33; 32])]),
        };
        let head = FullTreeHead::Updated {
            tree_head: TreeHead {
                tree_size: 4,
                signature: vec![9; 64],
            },
            auditor_tree_head: None,
        };

        let contact = ContactMonitorResponse {
            full_tree_head: head.clone(),
            monitor: proof.clone(),
        };
        let bytes = encode(&contact).unwrap();
        let mut dec = Decoder::new(&bytes);
        assert_eq!(
            ContactMonitorResponse::decode_with(&mut dec, DeploymentMode::ContactMonitoring)
                .unwrap(),
            contact
        );

        let owner = OwnerMonitorResponse {
            full_tree_head: head.clone(),
            monitor: proof.clone(),
        };
        let bytes = encode(&owner).unwrap();
        let mut dec = Decoder::new(&bytes);
        assert_eq!(
            OwnerMonitorResponse::decode_with(&mut dec, DeploymentMode::ContactMonitoring).unwrap(),
            owner
        );
        // The two are byte-identical for the same contents, which is exactly why they are
        // separate types: only the request says which algorithm ordered the proof inside.
        assert_eq!(encode(&contact).unwrap(), encode(&owner).unwrap());

        let init = OwnerInitResponse {
            full_tree_head: head,
            greatest_versions: vec![9, 4, 1],
            binary_ladder: vec![BinaryLadderStep {
                proof: vec![0x44; 80],
                commitment: Some(HashValue::from_bytes([0x55; 32])),
            }],
            init: proof,
        };
        let bytes = encode(&init).unwrap();
        let mut dec = Decoder::new(&bytes);
        assert_eq!(
            OwnerInitResponse::decode_with(&mut dec, DeploymentMode::ContactMonitoring, 80)
                .unwrap(),
            init
        );
    }

    /// The same bytes read with the wrong idea of what was requested. Four bytes shift, and
    /// everything after them is read out of position — which is the failure the context
    /// parameters exist to prevent, and the reason they are not defaulted.
    #[test]
    fn the_version_field_depends_on_the_request() {
        let bytes = encode(&response(Some(4))).unwrap();
        let mut dec = Decoder::new(&bytes);
        let misread =
            SearchResponse::decode_with(&mut dec, DeploymentMode::ContactMonitoring, 16, 80, true);
        match misread {
            Err(_) => {}
            Ok(decoded) => assert_ne!(
                decoded,
                response(Some(4)),
                "reading a greatest-version response as a fixed-version one must not \
                 reproduce it"
            ),
        }
    }
}
