//! Third-party auditing (§15.2).
//!
//! In the third-party auditing deployment mode the log has to convince an auditor that
//! it built each new entry correctly before the auditor will sign an `AuditorTreeHead`
//! covering it. The auditor is not a user and not a mirror: it holds no tree, only the
//! roots it has already accepted. So everything it needs to check an entry has to arrive
//! in one structure, which is this one.
//!
//! The asymmetry is the interesting part. A user proves *membership* — one label, one
//! version, a path. An auditor proves *transition*: that the prefix tree went from the
//! root it already has to the root the new entry claims, by exactly the leaves listed.
//! That is why the proof here covers a batch of keys in the *previous* entry's tree
//! rather than the current one.
//!
//! The verification itself lives in `kt-tree`, which is where the trees are;
//! `kt_tree::audit` implements the steps §15.2 lists, and
//! `kt_tree::prefix::evaluate_before_after` does steps 6 and 7.

use crate::codec::{Decode, Decoder, Encode, Encoder, Result, VectorSpec};
use crate::proofs::{PrefixLeaf, PrefixProof};
use alloc::vec::Vec;

/// Everything an auditor needs to accept one new log entry (§15.2).
///
/// ```text
/// struct {
///   uint64 timestamp;
///
///   PrefixLeaf added<0..2^16-1>;
///   PrefixLeaf removed<0..2^16-1>;
///
///   PrefixProof proof;
/// } AuditorUpdate;
/// ```
///
/// `timestamp` is the new log entry's, and must not go backwards (step 1). `added` and
/// `removed` are the prefix tree leaves the entry adds and removes, each sorted
/// ascending by `vrf_output` with no repeats *within* a list — though the same
/// `vrf_output` may appear in both, which is how a label's value is replaced (step 2).
///
/// `proof` is a single batch lookup in the *previous* entry's prefix tree covering every
/// search key either list names, with `proof.results` ordered as `added` then `removed`.
/// Note what that ordering implies: the results are pinned to the keys being changed, so
/// there is no way for the update to describe any other node — including the sibling of
/// a leaf being removed, which §3.3's canonical form may need. See
/// `kt_tree::prefix::evaluate_before_after`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditorUpdate {
    /// The new log entry's timestamp, in milliseconds since the UNIX epoch.
    pub timestamp: u64,
    /// Prefix tree leaves this entry adds.
    pub added: Vec<PrefixLeaf>,
    /// Prefix tree leaves this entry removes.
    pub removed: Vec<PrefixLeaf>,
    /// A batch lookup in the previous entry's prefix tree for every key named above.
    pub proof: PrefixProof,
}

impl AuditorUpdate {
    /// `PrefixLeaf added<0..2^16-1>`, and the same for `removed`.
    ///
    /// §2.1.2 as this draft uses it counts *elements*, not bytes, so the bound is 65535
    /// leaves rather than 65535 bytes' worth of them.
    pub const LEAVES: VectorSpec = VectorSpec::new((1 << 16) - 1);
}

impl Encode for AuditorUpdate {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        self.timestamp.encode(enc)?;
        enc.vector(Self::LEAVES, &self.added)?;
        enc.vector(Self::LEAVES, &self.removed)?;
        self.proof.encode(enc)
    }
}

impl Decode for AuditorUpdate {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
        let timestamp = u64::decode(dec)?;
        let added = dec.vector(Self::LEAVES)?;
        let removed = dec.vector(Self::LEAVES)?;
        let proof = PrefixProof::decode(dec)?;
        Ok(Self {
            timestamp,
            added,
            removed,
            proof,
        })
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
    use crate::codec::{decode, encode};
    use crate::proofs::PrefixSearchResult;
    use crate::structs::HashValue;
    use alloc::vec;

    fn leaf(byte: u8) -> PrefixLeaf {
        PrefixLeaf {
            vrf_output: HashValue::from_bytes([byte; HashValue::SIZE]),
            commitment: HashValue::from_bytes([byte ^ 0xff; HashValue::SIZE]),
        }
    }

    fn update() -> AuditorUpdate {
        AuditorUpdate {
            timestamp: 1_700_000_000_000,
            added: vec![leaf(0x11), leaf(0x22)],
            removed: vec![leaf(0x33)],
            proof: PrefixProof {
                results: vec![
                    PrefixSearchResult::NonInclusionParent { depth: 3 },
                    PrefixSearchResult::NonInclusionLeaf {
                        leaf: leaf(0x44),
                        depth: 5,
                    },
                    PrefixSearchResult::Inclusion { depth: 7 },
                ],
                elements: vec![HashValue::from_bytes([0xab; HashValue::SIZE])],
            },
        }
    }

    #[test]
    fn round_trips() {
        let bytes = encode(&update()).unwrap();
        assert_eq!(decode::<AuditorUpdate>(&bytes).unwrap(), update());
    }

    #[test]
    fn the_length_prefixes_count_leaves() {
        let bytes = encode(&update()).unwrap();
        // timestamp, then a uint16 of 2 for `added`, then two 64-byte leaves.
        assert_eq!(&bytes[..8], &1_700_000_000_000_u64.to_be_bytes());
        assert_eq!(&bytes[8..10], &[0, 2]);
        assert_eq!(&bytes[10..42], &[0x11; 32]);
        // And a uint16 of 1 for `removed`, after the 128 bytes of `added`.
        assert_eq!(&bytes[138..140], &[0, 1]);
    }

    #[test]
    fn an_empty_update_is_representable() {
        // The log may add an entry that changes no prefix tree leaves at all: §15.2 puts
        // no lower bound on either list, and a zero-length vector is one length prefix.
        let empty = AuditorUpdate {
            timestamp: 0,
            added: Vec::new(),
            removed: Vec::new(),
            proof: PrefixProof {
                results: Vec::new(),
                elements: Vec::new(),
            },
        };
        // Eight bytes of timestamp, a uint16 each for `added` and `removed`, then the
        // proof's own two prefixes — a uint8 for `results<0..2^8-1>` and a uint16 for
        // `elements<0..2^16-1>`.
        let bytes = encode(&empty).unwrap();
        assert_eq!(bytes.len(), 8 + 2 + 2 + 1 + 2);
        assert_eq!(decode::<AuditorUpdate>(&bytes).unwrap(), empty);
    }

    #[test]
    fn a_truncated_update_is_rejected() {
        let bytes = encode(&update()).unwrap();
        for cut in 0..bytes.len() {
            assert!(
                decode::<AuditorUpdate>(&bytes[..cut]).is_err(),
                "a {cut}-byte prefix decoded"
            );
        }
    }
}
