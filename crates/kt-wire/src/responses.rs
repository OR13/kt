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
use crate::requests::{BinaryLadderStep, LabelValue, UpdateInfo};
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

/// The log's answer to an `UpdateRequest` (§13.5).
///
/// ```text
/// struct {
///   FullTreeHead full_tree_head;
///
///   uint64 position;
///   LabelValue values<0..2^8-1>;
///   UpdateInfo info<0..2^8-1>;
///
///   BinaryLadderStep binary_ladder<0..2^8-1>;
///   CombinedTreeProof update;
/// } UpdateResponse;
/// ```
///
/// `position` is where the new versions were inserted, and §13.5 warns that it "may or may not be
/// the rightmost log entry" — an update is sequenced into whatever entry the log is building, and
/// entries to its right may already exist by the time the response is sent.
///
/// `values` carries a meaning by its emptiness rather than its contents. Empty means every version
/// in the request was created and nothing else was: the ordinary success. Non-empty means the
/// request was *disregarded* — the user's `greatest_version` was behind, so the log is reporting
/// the versions that already exist above it instead. `info` corresponds to whichever list is in
/// play, one element per version created, and §13.5 step 2 requires it to be non-empty either way.
///
/// # One request, several responses
///
/// §13.5 lets a log answer one `UpdateRequest` with a *stream* of `UpdateResponse`s, each covering
/// a later `position`. They are processed "serially as if an `UpdateRequest` with the following
/// parameters had been sent": `last` set to the previous response's tree size, `greatest_version`
/// advanced over the versions it reported, and `values` left alone "until the first
/// `UpdateResponse` with an empty `values` field is received", empty from then on.
///
/// That last rule is the subtle one, and it follows from what an empty `values` means. Until an
/// empty one arrives the log has been reporting versions the user did not ask for, so the user's
/// own values are still outstanding; the response that comes back empty is the one that finally
/// created them, and there is nothing left to submit. A client that kept resubmitting would ask
/// for the same values twice.
///
/// The state each step advances is the owner state of
/// [`kt_tree::combined::owner_update`](../../kt_tree/combined/fn.owner_update.html), which is why
/// there is no combined "verify the stream" entry point here: each response is verified against the
/// state the previous one produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateResponse {
    /// The tree head, and the auditor's where the mode has one.
    pub full_tree_head: FullTreeHead,
    /// The log entry the new versions were inserted into.
    pub position: u64,
    /// The values created, when the request was disregarded; empty when it was honoured.
    pub values: Vec<LabelValue>,
    /// One entry per version created: its commitment opening, and its signature under
    /// `thirdPartyManagement`.
    pub info: Vec<UpdateInfo>,
    /// One step per version in §9.1's version set, ascending by version.
    pub binary_ladder: Vec<BinaryLadderStep>,
    /// The proof: the view update, then §9.1's algorithm.
    pub update: CombinedTreeProof,
}

impl UpdateResponse {
    /// `LabelValue values<0..2^8-1>`.
    pub const VALUES: VectorSpec = VectorSpec::new((1 << 8) - 1);
    /// `UpdateInfo info<0..2^8-1>`.
    pub const INFO: VectorSpec = VectorSpec::new((1 << 8) - 1);
    /// `BinaryLadderStep binary_ladder<0..2^8-1>`.
    pub const LADDER: VectorSpec = VectorSpec::new((1 << 8) - 1);

    /// Reads an `UpdateResponse` under `mode`, with `nc`-byte openings and `VRF.Np`-byte proofs.
    ///
    /// # Errors
    ///
    /// Codec errors from any member.
    pub fn decode_with(
        dec: &mut Decoder<'_>,
        mode: DeploymentMode,
        nc: usize,
        proof_size: usize,
    ) -> Result<Self> {
        let full_tree_head = FullTreeHead::decode_with_mode(dec, mode)?;
        let position = dec.u64()?;
        let values = dec.vector(Self::VALUES)?;
        let info = dec.vector_with(Self::INFO, |dec| UpdateInfo::decode_with(dec, nc, mode))?;
        let binary_ladder = dec.vector_with(Self::LADDER, |dec| {
            BinaryLadderStep::decode_with_proof_size(dec, proof_size)
        })?;
        let update = CombinedTreeProof::decode(dec)?;
        Ok(Self {
            full_tree_head,
            position,
            values,
            info,
            binary_ladder,
            update,
        })
    }
}

impl Encode for UpdateResponse {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        self.full_tree_head.encode(enc)?;
        enc.u64(self.position);
        enc.vector(Self::VALUES, &self.values)?;
        enc.vector(Self::INFO, &self.info)?;
        enc.vector(Self::LADDER, &self.binary_ladder)?;
        self.update.encode(enc)
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
    use crate::proofs::{InclusionProof, PrefixLeaf, PrefixProof, PrefixSearchResult};
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

    /// An update response round-trips under `thirdPartyManagement`, which is the mode with the most
    /// context-dependent parts: an `UpdateInfo` carries both an `Nc`-byte opening and a signature
    /// suffix, and neither length is on the wire.
    #[test]
    fn an_update_response_round_trips() {
        let value = UpdateResponse {
            full_tree_head: FullTreeHead::Updated {
                tree_head: TreeHead {
                    tree_size: 12,
                    signature: vec![3; 64],
                },
                auditor_tree_head: None,
            },
            position: 9,
            values: vec![LabelValue::new(vec![1, 2, 3])],
            info: vec![UpdateInfo {
                opening: vec![0xcd; 16],
                suffix: UpdateSuffix::ThirdPartyManagement {
                    signature: vec![0xef; 64],
                },
            }],
            binary_ladder: vec![BinaryLadderStep {
                proof: vec![0x77; 80],
                commitment: None,
            }],
            update: CombinedTreeProof {
                timestamps: vec![5],
                prefix_proofs: vec![PrefixProof {
                    results: vec![PrefixSearchResult::NonInclusionLeaf {
                        leaf: PrefixLeaf {
                            vrf_output: HashValue::from_bytes([0x88; 32]),
                            commitment: HashValue::from_bytes([0x89; 32]),
                        },
                        depth: 3,
                    }],
                    elements: vec![HashValue::from_bytes([0x99; 32])],
                }],
                prefix_roots: Vec::new(),
                inclusion: InclusionProof::new(Vec::new()),
            },
        };
        let bytes = encode(&value).unwrap();
        let mut dec = Decoder::new(&bytes);
        let decoded =
            UpdateResponse::decode_with(&mut dec, DeploymentMode::ThirdPartyManagement, 16, 80)
                .unwrap();
        assert_eq!(decoded, value);
    }

    /// The empty cases, all of which §13.5 gives a meaning to. `values` empty means the request was
    /// honoured; `binary_ladder` empty means every search key the update needs is one the owner
    /// already holds, which is the common case for a single-version update. Both have to survive a
    /// round-trip as *empty* rather than being read as absent.
    #[test]
    fn an_update_response_with_nothing_optional_round_trips() {
        let value = UpdateResponse {
            full_tree_head: FullTreeHead::Same,
            position: 0,
            values: Vec::new(),
            info: vec![UpdateInfo {
                opening: vec![0; 16],
                suffix: UpdateSuffix::Empty,
            }],
            binary_ladder: Vec::new(),
            update: CombinedTreeProof {
                timestamps: Vec::new(),
                prefix_proofs: Vec::new(),
                prefix_roots: Vec::new(),
                inclusion: InclusionProof::new(Vec::new()),
            },
        };
        let bytes = encode(&value).unwrap();
        let mut dec = Decoder::new(&bytes);
        let decoded =
            UpdateResponse::decode_with(&mut dec, DeploymentMode::ContactMonitoring, 16, 80)
                .unwrap();
        assert_eq!(decoded, value);
        assert!(decoded.values.is_empty() && decoded.binary_ladder.is_empty());
    }
}
