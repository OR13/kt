//! Client algorithms for IETF Key Transparency.
//!
//! Implements the client-side algorithms of `draft-ietf-keytrans-protocol`
//! §4.2 and §6–§10, and the user operations that carry them in §13.
//!
//! # Operations
//!
//! - **Updating a view of the tree** (§4.2) — the precondition for everything else.
//! - **Greatest-version search** (§6) and **fixed-version search** (§7),
//!   exposed as the `Search` operation (§13.1).
//! - **Monitoring the tree** (§8) — the contact algorithm (§8.2, §13.2) and the
//!   owner algorithm (§8.3, §13.3, §13.4).
//! - **Updating a label** (§9, §13.5).
//! - **Walking distinguished heads** (§10, §13.6), including fork detection
//!   (§10.2, and §14.2.1 for provisional credentials).
//! - **Credentials** (§14) and third-party **auditing** (§15.2).
//!
//! # Why this crate is last
//!
//! These algorithms are compositions: they are only meaningfully testable once
//! the wire codec, the crypto, and the trees all agree with the Go peers.
//! Interop here takes the form of transcripts rather than single values — see
//! `docs/interop.md` Tier 1 step 8 and Tier 2.
//!
//! # Security posture
//!
//! This is verification code. A client that *over-accepts* — that verifies a
//! proof the Go clients reject — is broken in exactly the way that happy-path
//! equality testing cannot see. Negative vectors are not optional here, and
//! `upstream/keytrans-verification`'s Gobra preconditions are the best available
//! catalogue of what must be checked.

/// Maintaining and advancing a client's view of the tree
/// (`draft-ietf-keytrans-protocol-05` §4.2, §12.3.1).
pub mod view {
    // TODO(interop tier 1, step 8).
}

/// Greatest-version and fixed-version search
/// (`draft-ietf-keytrans-protocol-05` §6, §7, §13.1).
pub mod search {
    // TODO(interop tier 1, step 8).
}

/// Contact and owner monitoring
/// (`draft-ietf-keytrans-protocol-05` §8, §13.2–§13.4).
pub mod monitor {
    // TODO(interop tier 1, step 8).
}

/// Updating a label (`draft-ietf-keytrans-protocol-05` §9, §13.5).
pub mod update {
    // TODO(interop tier 1, step 8).
}

/// Walking distinguished heads and detecting forks
/// (`draft-ietf-keytrans-protocol-05` §10, §13.6).
pub mod distinguished {
    // TODO(interop tier 2, step 4).
}

/// Third-party auditor verification (`draft-ietf-keytrans-protocol-05` §15.2).
pub mod auditor {
    // TODO(interop tier 2).
}
