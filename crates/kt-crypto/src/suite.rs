//! Cipher suite definitions and the primitives they select
//! (`draft-ietf-keytrans-protocol-05` §11.1, registry §17.1).

use core::fmt;

/// Size in bytes of a commitment opening (`Nc`) for both registered suites.
pub const NC: usize = 16;

/// Output length in bytes of the hash function (`Hash.Nh`) for both registered
/// suites.
pub const NH: usize = 32;

/// The fixed commitment key `Kc` shared by both registered suites (§17.1).
pub const KC: [u8; NC] = [
    0xd8, 0x21, 0xf8, 0x79, 0x0d, 0x97, 0x70, 0x97, 0x96, 0xb4, 0xd7, 0x90, 0x33, 0x57, 0xc3, 0xf5,
];

/// A cipher suite from the registry in §17.1.
///
/// Both registered suites use SHA-256, `Nc = 16`, `Hash.Nh = 32`, `VRF.Nh = 32`,
/// and the same `Kc`; they differ only in the signature and VRF algorithms. So
/// every §11.6 commitment is the same computation regardless of suite, and this
/// type is carried through anyway — a future suite with a different hash or `Nc`
/// must not silently reuse SHA-256.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum CipherSuite {
    /// `KT_128_SHA256_P256` (`0x0001`): ECDSA/P-256 and ECVRF-P256-SHA256-TAI.
    Kt128Sha256P256,
    /// `KT_128_SHA256_Ed25519` (`0x0002`): Ed25519 and
    /// ECVRF-EDWARDS25519-SHA512-TAI truncated to 32 bytes.
    Kt128Sha256Ed25519,
}

impl CipherSuite {
    /// The registry value, as it appears in the `CipherSuite` uint16.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Kt128Sha256P256 => 0x0001,
            Self::Kt128Sha256Ed25519 => 0x0002,
        }
    }

    /// Parses a registry value.
    ///
    /// # Errors
    ///
    /// [`UnknownCipherSuite`] for `0x0000` (RESERVED), the private-use range,
    /// and anything else not in §17.1. An unrecognized suite is not something to
    /// guess at: it determines the hash, so guessing means computing the wrong
    /// bytes.
    pub const fn from_code(code: u16) -> Result<Self, UnknownCipherSuite> {
        match code {
            0x0001 => Ok(Self::Kt128Sha256P256),
            0x0002 => Ok(Self::Kt128Sha256Ed25519),
            other => Err(UnknownCipherSuite(other)),
        }
    }

    /// `Nc`: the size in bytes of a commitment opening.
    #[must_use]
    pub const fn nc(self) -> usize {
        NC
    }

    /// `Hash.Nh`: the hash function's output length in bytes.
    #[must_use]
    pub const fn nh(self) -> usize {
        NH
    }

    /// `Kc`: the fixed byte string used in commitments.
    #[must_use]
    pub const fn kc(self) -> &'static [u8] {
        &KC
    }

    /// The suite's name as it appears in the registry.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Kt128Sha256P256 => "KT_128_SHA256_P256",
            Self::Kt128Sha256Ed25519 => "KT_128_SHA256_Ed25519",
        }
    }
}

impl fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A `CipherSuite` value that is not in the §17.1 registry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UnknownCipherSuite(pub u16);

impl fmt::Display for UnknownCipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown cipher suite 0x{:04x}", self.0)
    }
}

impl core::error::Error for UnknownCipherSuite {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_values_round_trip() {
        for suite in [
            CipherSuite::Kt128Sha256P256,
            CipherSuite::Kt128Sha256Ed25519,
        ] {
            assert_eq!(CipherSuite::from_code(suite.code()), Ok(suite));
        }
        assert_eq!(CipherSuite::Kt128Sha256P256.code(), 1);
        assert_eq!(CipherSuite::Kt128Sha256Ed25519.code(), 2);
    }

    #[test]
    fn reserved_and_private_use_are_not_suites() {
        for code in [0x0000, 0x0003, 0xf000, 0xffff] {
            assert_eq!(CipherSuite::from_code(code), Err(UnknownCipherSuite(code)));
        }
    }

    /// §17.1: `Kc` is the hex string `d821f8790d97709796b4d7903357c3f5`.
    #[test]
    fn kc_matches_the_registry() {
        assert_eq!(KC.len(), NC);
        let hex: alloc::string::String = KC.iter().map(|b| alloc::format!("{b:02x}")).collect();
        assert_eq!(hex, "d821f8790d97709796b4d7903357c3f5");
    }
}
