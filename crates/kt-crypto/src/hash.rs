//! The cipher suite's hash function (`draft-ietf-keytrans-protocol-05` §11.1).
//!
//! Both suites in the §17.1 registry hash with SHA-256, so this is one function
//! with a suite argument that currently only ever selects SHA-256. It exists so
//! that the tree code in `kt-tree` names the *suite's* hash rather than reaching
//! for a concrete algorithm — the tree hashing rules in §11.8 and §11.9 are
//! defined in terms of `Hash`, and a suite with a different one must not silently
//! keep hashing with this one.
//!
//! The `parts` argument is a list of byte strings to hash in order. The draft's
//! hashing rules are all concatenations with domain-separating prefix bytes —
//! `0x00`/`0x01` for the log tree, `0x02`/`0x03` for the prefix tree — and
//! passing the pieces separately keeps the call site looking like the rule it
//! implements without allocating the concatenation first.

use sha2::{Digest as _, Sha256};

use kt_wire::structs::HashValue;

use crate::suite::CipherSuite;

/// Hashes the concatenation of `parts` with the suite's hash function.
///
/// ```
/// use kt_crypto::hash;
/// use kt_crypto::suite::CipherSuite;
///
/// // The two calls are the same computation; the split is for readability.
/// let split = hash::hash(CipherSuite::Kt128Sha256Ed25519, &[&[0x02], b"key", b"value"]);
/// let whole = hash::hash(CipherSuite::Kt128Sha256Ed25519, &[b"\x02keyvalue"]);
/// assert_eq!(split, whole);
/// ```
#[must_use]
pub fn hash(suite: CipherSuite, parts: &[&[u8]]) -> HashValue {
    match suite {
        // Both registered suites hash with SHA-256 (§17.1). A future suite with
        // a different hash function must add an arm here.
        CipherSuite::Kt128Sha256P256 | CipherSuite::Kt128Sha256Ed25519 => {
            let mut hasher = Sha256::new();
            for part in parts {
                hasher.update(part);
            }
            HashValue::from_bytes(hasher.finalize().into())
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail loudly by panicking; the lint protects library paths"
)]
mod tests {
    use super::*;

    const SUITE: CipherSuite = CipherSuite::Kt128Sha256Ed25519;

    /// The empty SHA-256 digest, so a wrong hash function would be obvious.
    #[test]
    fn hashes_with_sha256() {
        let digest = hash(SUITE, &[]);
        assert_eq!(
            hex_of(digest.as_bytes()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn parts_are_concatenated_in_order() {
        assert_eq!(hash(SUITE, &[b"ab", b"c"]), hash(SUITE, &[b"abc"]));
        assert_ne!(hash(SUITE, &[b"ab", b"c"]), hash(SUITE, &[b"ac", b"b"]));
    }

    /// The prefix bytes in §11.8 and §11.9 are domain separators, and they only
    /// work if they actually change the digest.
    #[test]
    fn prefix_bytes_separate_domains() {
        let payload: &[u8] = b"same payload";
        let log_leaf = hash(SUITE, &[&[0x00], payload]);
        let log_parent = hash(SUITE, &[&[0x01], payload]);
        let prefix_leaf = hash(SUITE, &[&[0x02], payload]);
        let prefix_parent = hash(SUITE, &[&[0x03], payload]);
        let all = [log_leaf, log_parent, prefix_leaf, prefix_parent];
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i.saturating_add(1)) {
                assert_ne!(a, b);
            }
        }
    }

    fn hex_of(bytes: &[u8]) -> alloc::string::String {
        bytes.iter().map(|b| alloc::format!("{b:02x}")).collect()
    }
}
