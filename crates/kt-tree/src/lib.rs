//! Tree construction for IETF Key Transparency.
//!
//! Implements the three trees of `draft-ietf-keytrans-protocol` §3, their
//! hashing rules (§11.8, §11.9), the integer math that navigates them (§4.1,
//! Appendix A), the binary ladder (§5, Appendix B), and the proof types over
//! them (§12, Appendix C).
//!
//! # The trees
//!
//! - **Log tree** (§3.2) — append-only, one leaf per update, provides inclusion
//!   and consistency proofs. Hashing in §11.8, proofs in §12.1.
//! - **Prefix tree** (§3.3) — maps VRF outputs to versions, provides membership
//!   and non-membership proofs. Hashing in §11.9, proofs in §12.2. The subtlest
//!   hashing in the draft; expect the first interop mismatches here.
//! - **Combined tree** (§3.4) — the log tree whose leaves commit to prefix-tree
//!   roots, which is what a `TreeHead` actually signs. Proofs in §12.3, with the
//!   serialization walked through in Appendix C.
//!
//! # Integer math
//!
//! The implicit binary search tree (§4.1) and the binary ladder (§5) are pure
//! integer functions with pseudocode in Appendices A and B. They need no
//! cryptography, no state, and no I/O — which makes them the cheapest
//! high-confidence interop win available. Do them early.

/// Append-only log tree (`draft-ietf-keytrans-protocol-05` §3.2, §11.8, §12.1).
pub mod log {
    // TODO(interop tier 1, step 4).
}

/// Prefix tree over VRF outputs (`draft-ietf-keytrans-protocol-05` §3.3, §11.9, §12.2).
pub mod prefix {
    // TODO(interop tier 1, step 5).
}

/// Combined tree — log leaves committing to prefix roots
/// (`draft-ietf-keytrans-protocol-05` §3.4, §12.3, Appendix C).
pub mod combined {
    // TODO(interop tier 1, step 7).
}

/// Implicit binary search tree over log positions
/// (`draft-ietf-keytrans-protocol-05` §4.1, Appendix A).
pub mod ibst {
    // TODO(interop tier 1, step 6): log2, level, root, left, right.
}

/// Binary ladder construction (`draft-ietf-keytrans-protocol-05` §5, Appendix B).
///
/// Three variants: the greatest-version ladder (§6.2), the search ladder for a
/// target version (§6.2), and the monitoring ladder (§8.1).
pub mod ladder {
    // TODO(interop tier 1, step 6).
}
