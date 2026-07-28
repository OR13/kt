//! Tree proof types (`draft-ietf-keytrans-protocol-05` §12).
//!
//! The wire shapes only; the algorithms that build and check them are in
//! `kt-tree`. Two of them are worth reading the module documentation for before
//! use, because their encodings are easy to get subtly wrong:
//!
//! - [`InclusionProof`] is a *batch* proof (§12.1). It covers inclusion for a set
//!   of leaves and consistency against subtree heads the verifier has retained,
//!   in one `elements` array, ordered left to right through the tree.
//! - [`PrefixProof`] (§12.2) carries one [`PrefixSearchResult`] per lookup, in the
//!   order requested, plus the copath values. Both of its vectors are counted in
//!   *elements*, not bytes — §2.1.2 — which for `elements` means the byte length
//!   is 32 times the prefix.

use alloc::vec::Vec;

use crate::codec::{Decode, Decoder, Encode, Encoder, Error, Result, VectorSpec};
use crate::structs::HashValue;

/// A batch inclusion and consistency proof from the log tree (§12.1).
///
/// ```tls-presentation
/// struct {
///   HashValue elements<0..2^16-1>;
/// } InclusionProof;
/// ```
///
/// `elements` holds "the minimum set of head values from balanced subtrees that
/// allows the user to compute the root value when combined with the leaf and
/// retained values", in left-to-right order: a node in the root's left subtree
/// comes before any node in the root's right subtree, recursively.
///
/// Because the proof is minimal, it is not self-describing: the verifier has to
/// know which leaves are being proven and which subtree heads it retained in
/// order to know what each element is. That context is what makes §12.1's
/// warning load-bearing — see `kt_tree::log::verify_inclusion`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InclusionProof {
    /// Subtree head values, left to right.
    pub elements: Vec<HashValue>,
}

impl InclusionProof {
    /// `HashValue elements<0..2^16-1>`.
    pub const ELEMENTS: VectorSpec = VectorSpec::new((1 << 16) - 1);

    /// A proof carrying `elements`.
    #[must_use]
    pub const fn new(elements: Vec<HashValue>) -> Self {
        Self { elements }
    }
}

impl Encode for InclusionProof {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.vector(Self::ELEMENTS, &self.elements)
    }
}

impl Decode for InclusionProof {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        Ok(Self {
            elements: dec.vector(Self::ELEMENTS)?,
        })
    }
}

/// A leaf of the prefix tree (§12.2 `PrefixLeaf`).
///
/// ```tls-presentation
/// struct {
///   opaque vrf_output[VRF.Nh];
///   opaque commitment[Hash.Nh];
/// } PrefixLeaf;
/// ```
///
/// `vrf_output` is the search key — the VRF evaluation of a label-version pair
/// (§11.7) — and `commitment` is the §11.6 commitment to the `UpdateValue`. Both
/// are 32 bytes here, but for different reasons: `VRF.Nh` and `Hash.Nh` are
/// separate cipher-suite parameters that happen to coincide for both registered
/// suites.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PrefixLeaf {
    /// The search key: the VRF output for a label-version pair.
    pub vrf_output: HashValue,
    /// The commitment to the corresponding `UpdateValue`.
    pub commitment: HashValue,
}

impl Encode for PrefixLeaf {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        self.vrf_output.encode(enc)?;
        self.commitment.encode(enc)
    }
}

impl Decode for PrefixLeaf {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        let vrf_output = HashValue::decode(dec)?;
        let commitment = HashValue::decode(dec)?;
        Ok(Self {
            vrf_output,
            commitment,
        })
    }
}

/// What a prefix-tree search terminated on (§12.2 `PrefixSearchResultType`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PrefixSearchResultType {
    /// `inclusion(1)`: a leaf matching the requested search key.
    Inclusion,
    /// `nonInclusionLeaf(2)`: a leaf for a *different* search key.
    NonInclusionLeaf,
    /// `nonInclusionParent(3)`: a parent lacking the desired child.
    NonInclusionParent,
}

impl PrefixSearchResultType {
    /// The registry value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Inclusion => 1,
            Self::NonInclusionLeaf => 2,
            Self::NonInclusionParent => 3,
        }
    }

    /// Parses a registry value.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEnum`] for `reserved(0)` and anything above 3.
    pub const fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Inclusion),
            2 => Ok(Self::NonInclusionLeaf),
            3 => Ok(Self::NonInclusionParent),
            other => Err(Error::InvalidEnum {
                name: "PrefixSearchResultType",
                value: other as u64,
            }),
        }
    }
}

/// The result of one prefix-tree lookup (§12.2 `PrefixSearchResult`).
///
/// ```tls-presentation
/// struct {
///   PrefixSearchResultType result_type;
///   select (PrefixSearchResult.result_type) {
///     case nonInclusionLeaf:
///       PrefixLeaf leaf;
///   };
///   uint8 depth;
/// } PrefixSearchResult;
/// ```
///
/// Note the field order: the leaf, when present, sits *between* the type and the
/// depth. `depth` is the depth of the terminal node, with the root at 0.
///
/// The `nonInclusionLeaf` case carries the leaf because, unlike the other two, it
/// cannot be inferred: the verifier has to hash a leaf it did not ask for.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PrefixSearchResult {
    /// The search found a leaf for the requested key.
    Inclusion {
        /// Depth of the terminal node; the root is 0.
        depth: u8,
    },
    /// The search ended at a leaf for a different key, given here.
    NonInclusionLeaf {
        /// The leaf that was found instead.
        leaf: PrefixLeaf,
        /// Depth of the terminal node; the root is 0.
        depth: u8,
    },
    /// The search ended at a parent that lacks the child it needed.
    NonInclusionParent {
        /// Depth of the terminal node; the root is 0.
        depth: u8,
    },
}

impl PrefixSearchResult {
    /// This result's type tag.
    #[must_use]
    pub const fn result_type(&self) -> PrefixSearchResultType {
        match self {
            Self::Inclusion { .. } => PrefixSearchResultType::Inclusion,
            Self::NonInclusionLeaf { .. } => PrefixSearchResultType::NonInclusionLeaf,
            Self::NonInclusionParent { .. } => PrefixSearchResultType::NonInclusionParent,
        }
    }

    /// The depth of the terminal node.
    #[must_use]
    pub const fn depth(&self) -> u8 {
        match self {
            Self::Inclusion { depth }
            | Self::NonInclusionLeaf { depth, .. }
            | Self::NonInclusionParent { depth } => *depth,
        }
    }

    /// Whether this result proves the requested key is present.
    #[must_use]
    pub const fn is_inclusion(&self) -> bool {
        matches!(self, Self::Inclusion { .. })
    }
}

impl Encode for PrefixSearchResult {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.u8(self.result_type().as_u8());
        if let Self::NonInclusionLeaf { leaf, .. } = self {
            leaf.encode(enc)?;
        }
        enc.u8(self.depth());
        Ok(())
    }
}

impl Decode for PrefixSearchResult {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        match PrefixSearchResultType::from_u8(dec.u8()?)? {
            PrefixSearchResultType::Inclusion => Ok(Self::Inclusion { depth: dec.u8()? }),
            PrefixSearchResultType::NonInclusionLeaf => {
                let leaf = PrefixLeaf::decode(dec)?;
                Ok(Self::NonInclusionLeaf {
                    leaf,
                    depth: dec.u8()?,
                })
            }
            PrefixSearchResultType::NonInclusionParent => {
                Ok(Self::NonInclusionParent { depth: dec.u8()? })
            }
        }
    }
}

/// A batch proof from the prefix tree (§12.2 `PrefixProof`).
///
/// ```tls-presentation
/// struct {
///   PrefixSearchResult results<0..2^8-1>;
///   HashValue elements<0..2^16-1>;
/// } PrefixProof;
/// ```
///
/// `results` corresponds one-to-one with the lookups requested, in order — for a
/// binary ladder, with the ladder's versions. `elements` holds "the fewest node
/// values that can be hashed together with the provided leaves to produce the
/// root", left to right, with [`HashValue::ZERO`] where a node does not exist.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrefixProof {
    /// One result per lookup, in the order requested.
    pub results: Vec<PrefixSearchResult>,
    /// Copath values, left to right, all-zero where a node is absent.
    pub elements: Vec<HashValue>,
}

impl PrefixProof {
    /// `PrefixSearchResult results<0..2^8-1>`.
    pub const RESULTS: VectorSpec = VectorSpec::new((1 << 8) - 1);
    /// `HashValue elements<0..2^16-1>`.
    pub const ELEMENTS: VectorSpec = VectorSpec::new((1 << 16) - 1);
}

impl Encode for PrefixProof {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        enc.vector(Self::RESULTS, &self.results)?;
        enc.vector(Self::ELEMENTS, &self.elements)
    }
}

impl Decode for PrefixProof {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        let results = dec.vector(Self::RESULTS)?;
        let elements = dec.vector(Self::ELEMENTS)?;
        Ok(Self { results, elements })
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

    fn hash(byte: u8) -> HashValue {
        HashValue::from_bytes([byte; HashValue::SIZE])
    }

    /// §2.1.2 again, and the reason it matters on the wire: the `elements` prefix
    /// counts hashes, so two elements are a prefix of 2 and a body of 64 bytes.
    #[test]
    fn inclusion_proof_elements_are_counted_not_measured() {
        let proof = InclusionProof::new(vec![hash(0xaa), hash(0xbb)]);
        let bytes = encode(&proof).unwrap();
        assert_eq!(
            &bytes[..2],
            &[0x00, 0x02],
            "two-byte prefix holding the count 2"
        );
        assert_eq!(bytes.len(), 2 + 64);
        assert_eq!(decode::<InclusionProof>(&bytes).unwrap(), proof);
    }

    #[test]
    fn empty_inclusion_proof_round_trips() {
        let proof = InclusionProof::default();
        let bytes = encode(&proof).unwrap();
        assert_eq!(bytes, vec![0x00, 0x00]);
        assert_eq!(decode::<InclusionProof>(&bytes).unwrap(), proof);
    }

    /// The field order from §12.2: type, then the leaf if the type calls for one,
    /// then depth. Getting this wrong shifts every following byte.
    #[test]
    fn search_result_puts_the_leaf_between_type_and_depth() {
        let leaf = PrefixLeaf {
            vrf_output: hash(0x01),
            commitment: hash(0x02),
        };
        let result = PrefixSearchResult::NonInclusionLeaf { leaf, depth: 7 };
        let bytes = encode(&result).unwrap();

        assert_eq!(bytes.len(), 1 + 64 + 1);
        assert_eq!(bytes[0], 2, "nonInclusionLeaf(2)");
        assert_eq!(
            bytes[1], 0x01,
            "vrf_output starts immediately after the type"
        );
        assert_eq!(bytes[33], 0x02, "commitment follows");
        assert_eq!(bytes[65], 7, "depth is last");
        assert_eq!(decode::<PrefixSearchResult>(&bytes).unwrap(), result);
    }

    #[test]
    fn search_results_without_a_leaf_are_two_bytes() {
        for (result, tag) in [
            (PrefixSearchResult::Inclusion { depth: 0 }, 1_u8),
            (PrefixSearchResult::NonInclusionParent { depth: 255 }, 3),
        ] {
            let bytes = encode(&result).unwrap();
            assert_eq!(bytes.len(), 2, "{result:?}");
            assert_eq!(bytes[0], tag);
            assert_eq!(bytes[1], result.depth());
            assert_eq!(decode::<PrefixSearchResult>(&bytes).unwrap(), result);
        }
    }

    #[test]
    fn reserved_and_unknown_result_types_are_rejected() {
        for tag in [0_u8, 4, 255] {
            assert_eq!(
                decode::<PrefixSearchResult>(&[tag, 0]),
                Err(Error::InvalidEnum {
                    name: "PrefixSearchResultType",
                    value: u64::from(tag)
                })
            );
        }
    }

    /// A `results` vector of variable-size elements: the one-byte prefix counts
    /// results, and the elements are 2, 66, and 2 bytes respectively.
    #[test]
    fn prefix_proof_round_trips_with_mixed_result_sizes() {
        let leaf = PrefixLeaf {
            vrf_output: hash(0x11),
            commitment: hash(0x22),
        };
        let proof = PrefixProof {
            results: vec![
                PrefixSearchResult::Inclusion { depth: 3 },
                PrefixSearchResult::NonInclusionLeaf { leaf, depth: 4 },
                PrefixSearchResult::NonInclusionParent { depth: 5 },
            ],
            elements: vec![hash(0x33), HashValue::ZERO],
        };
        let bytes = encode(&proof).unwrap();
        assert_eq!(bytes[0], 3, "three results");
        assert_eq!(bytes.len(), 1 + (2 + 66 + 2) + 2 + 64);
        assert_eq!(decode::<PrefixProof>(&bytes).unwrap(), proof);
    }

    /// §11.9's stand-in value has to survive a round trip as itself, not collapse
    /// into an absent element.
    #[test]
    fn zero_elements_survive_a_round_trip() {
        let proof = PrefixProof {
            results: Vec::new(),
            elements: vec![HashValue::ZERO],
        };
        let bytes = encode(&proof).unwrap();
        let back = decode::<PrefixProof>(&bytes).unwrap();
        assert_eq!(back, proof);
        assert!(back.elements[0].is_zero());
    }

    #[test]
    fn truncated_proofs_are_rejected() {
        // Claims two elements, provides one.
        assert!(decode::<InclusionProof>(&[0x00, 0x02, 0xaa]).is_err());
        // Claims one result, provides none.
        assert!(decode::<PrefixProof>(&[0x01]).is_err());
        // A nonInclusionLeaf result truncated inside its leaf.
        let mut bytes = vec![0x01, 0x02];
        bytes.extend_from_slice(&[0xcc; 40]);
        assert!(decode::<PrefixProof>(&bytes).is_err());
    }
}
