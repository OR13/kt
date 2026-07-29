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
