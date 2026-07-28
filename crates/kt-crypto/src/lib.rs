//! Cryptographic primitives for IETF Key Transparency.
//!
//! Implements the cryptographic computations of `draft-ietf-keytrans-protocol`
//! §11.
//!
//! # Cipher suites (§11.1, registry in §17.1)
//!
//! | Value | Name | Signature | VRF |
//! |---|---|---|---|
//! | `0x0001` | `KT_128_SHA256_P256` | ECDSA / P-256 | ECVRF-P256-SHA256-TAI |
//! | `0x0002` | `KT_128_SHA256_Ed25519` | Ed25519 | ECVRF-EDWARDS25519-SHA512-TAI |
//!
//! Both use SHA-256, `Nc = 16` (commitment opening size), `Hash.Nh = 32`,
//! `VRF.Nh = 32`, and the fixed commitment key
//! `Kc = d821f8790d97709796b4d7903357c3f5`.
//!
//! `KT_128_SHA256_Ed25519` is implemented first: both Go peers support it and it
//! has fewer point-encoding traps than P-256.

/// Cipher suite definitions and the primitives they select
/// (`draft-ietf-keytrans-protocol-05` §11.1, §17.1).
pub mod suite {
    /// Size in bytes of a commitment opening (`Nc`) for both registered suites.
    pub const NC: usize = 16;

    /// The fixed commitment key `Kc` shared by both registered suites (§17.1).
    pub const KC: [u8; NC] = [
        0xd8, 0x21, 0xf8, 0x79, 0x0d, 0x97, 0x70, 0x97, 0x96, 0xb4, 0xd7, 0x90, 0x33, 0x57, 0xc3,
        0xf5,
    ];
}

/// Commitments — `HMAC(Kc, CommitmentValue)`
/// (`draft-ietf-keytrans-protocol-05` §11.6).
pub mod commitment {
    // TODO(interop tier 1, step 1): commit / verify over a wire CommitmentValue.
}

/// Verifiable Random Function over `VrfInput{label, version}`
/// (`draft-ietf-keytrans-protocol-05` §11.7).
pub mod vrf {
    // TODO(interop tier 1, step 3): ECVRF for both registered suites.
}

/// Tree head, auditor tree head, and full tree head signatures
/// (`draft-ietf-keytrans-protocol-05` §11.2, §11.3, §11.4).
pub mod signature {
    // TODO(interop tier 1, step 7).
}

/// Update value format (`draft-ietf-keytrans-protocol-05` §11.5).
pub mod update_value {
    // TODO(interop tier 1, step 1): needed by the commitment vectors.
}
