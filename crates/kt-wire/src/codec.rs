//! Presentation-language primitives: optional values and variable-length
//! vectors (`draft-ietf-keytrans-protocol-05` §2.1).
//!
//! The draft describes protocol messages in the TLS presentation language
//! ([RFC 8446]) and requires that *cryptographic computations* use that encoding
//! even when a deployment ships some other transport encoding (§2.1). So this is
//! not merely a serialization convenience: these bytes are what gets hashed,
//! HMAC'd, and signed.
//!
//! # Deviation from RFC 8446 to be aware of
//!
//! §2.1.2 redefines the `<floor..ceiling>` notation: in RFC 8446 the bounds are
//! **byte** counts, in this draft they are **element** counts, and the length
//! prefix is wide enough to hold `ceiling`. For `opaque` vectors the two
//! readings coincide (elements are one byte each) but for something like
//! `uint32 greatest_versions<0..2^8-1>` (§13.3) they do not: the prefix is one
//! byte and counts elements, so the encoded body is four times the prefix value.
//! [`Encoder::vector`] and [`Decoder::vector`] implement the element-count
//! reading; [`Encoder::opaque_vector`] and [`Decoder::opaque_vector`] are the
//! byte-vector special case.
//!
//! [RFC 8446]: https://www.rfc-editor.org/rfc/rfc8446#section-3.4

use alloc::vec::Vec;
use core::fmt;

/// An encoding or decoding failure.
///
/// Decoding operates on adversary-controlled bytes, so every failure mode here
/// is reachable from the network and none of them may panic.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The decoder needed more bytes than the input had left.
    UnexpectedEof {
        /// Bytes the decoder asked for.
        needed: usize,
        /// Bytes actually available.
        remaining: usize,
    },
    /// Decoding produced a complete value but bytes were left over.
    ///
    /// Reported by [`decode`], which requires that a message be exactly
    /// consumed. Trailing bytes are a malleability vector: two distinct byte
    /// strings that decode to the same value would let a log show different
    /// bytes to different users while claiming the same structure.
    TrailingBytes {
        /// Bytes left after the value was decoded.
        remaining: usize,
    },
    /// A vector held more elements than its declared ceiling permits (§2.1.2).
    VectorTooLong {
        /// Element count seen.
        count: u64,
        /// Ceiling from the vector's `<floor..ceiling>` declaration.
        max: u64,
    },
    /// An optional value's presence octet was neither 0 nor 1 (§2.1.1).
    InvalidPresence {
        /// The offending octet.
        octet: u8,
    },
    /// An enum-typed field held a value outside its registry.
    InvalidEnum {
        /// Name of the enum in the draft, e.g. `DeploymentMode`.
        name: &'static str,
        /// The offending value.
        value: u64,
    },
    /// A fixed-size hash was the wrong length.
    HashLength {
        /// `Hash.Nh` for the suite in use.
        expected: usize,
        /// Length actually supplied.
        actual: usize,
    },
    /// A length or count did not fit in this platform's `usize`.
    ///
    /// Only reachable on 32-bit targets, where a `2^32-1` length prefix can
    /// exceed `usize::MAX`.
    LengthOverflow {
        /// The declared length or count.
        value: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof { needed, remaining } => {
                write!(
                    f,
                    "unexpected end of input: needed {needed} bytes, {remaining} remaining"
                )
            }
            Self::TrailingBytes { remaining } => {
                write!(f, "{remaining} trailing bytes after decoding")
            }
            Self::VectorTooLong { count, max } => {
                write!(f, "vector has {count} elements, ceiling is {max}")
            }
            Self::InvalidPresence { octet } => {
                write!(f, "optional presence octet must be 0 or 1, got {octet}")
            }
            Self::InvalidEnum { name, value } => {
                write!(f, "{value} is not a valid {name}")
            }
            Self::HashLength { expected, actual } => {
                write!(f, "hash must be {expected} bytes, got {actual}")
            }
            Self::LengthOverflow { value } => {
                write!(f, "length {value} does not fit in usize on this platform")
            }
        }
    }
}

impl core::error::Error for Error {}

/// A specialized [`Result`] for codec operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Width of the length prefix that precedes a variable-length vector.
///
/// §2.1.2: "The length will be in the form of a number consuming as many bytes
/// as required to hold the vector's specified maximum length." The draft uses
/// ceilings of `2^8-1`, `2^8`, `2^16-1`, and `2^32-1`, which need one, two, two,
/// and four bytes respectively — note that `<0..2^8>` (§10.1 `heads`) takes a
/// *two*-byte prefix, since 256 does not fit in one byte.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LengthPrefix {
    /// One-byte prefix; ceilings up to 255.
    U8,
    /// Two-byte prefix; ceilings up to 65535.
    U16,
    /// Four-byte prefix; ceilings up to 4294967295.
    U32,
}

impl LengthPrefix {
    /// The narrowest prefix that can express `max_count`.
    ///
    /// Ceilings above `u32::MAX` are not expressible; no vector in the draft has
    /// one, and [`VectorSpec::new`] is the only way to pair a ceiling with a
    /// prefix, so the pairing cannot be made inconsistent from outside.
    #[must_use]
    pub const fn for_max_count(max_count: u64) -> Self {
        if max_count <= u8::MAX as u64 {
            Self::U8
        } else if max_count <= u16::MAX as u64 {
            Self::U16
        } else {
            Self::U32
        }
    }

    /// Number of bytes this prefix occupies on the wire.
    #[must_use]
    pub const fn width(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U16 => 2,
            Self::U32 => 4,
        }
    }

    /// The largest count this prefix can express.
    #[must_use]
    pub const fn capacity(self) -> u64 {
        match self {
            Self::U8 => u8::MAX as u64,
            Self::U16 => u16::MAX as u64,
            Self::U32 => u32::MAX as u64,
        }
    }
}

/// A variable-length vector's `<floor..ceiling>` declaration (§2.1.2).
///
/// Constructed once per field as a `const`, so the ceiling that the decoder
/// enforces is the same one the encoder enforces, and both are visible next to
/// the field they describe:
///
/// ```
/// use kt_wire::codec::VectorSpec;
///
/// // opaque label<0..2^8-1>;
/// const LABEL: VectorSpec = VectorSpec::new(255);
/// assert_eq!(LABEL.prefix().width(), 1);
/// ```
///
/// The ceiling is enforced separately from the prefix width because they are not
/// the same constraint: `HashValue heads<0..2^8>` has a two-byte prefix, which
/// could express 65535 elements, but accepting more than 256 would be accepting
/// something the draft does not define.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VectorSpec {
    max_count: u64,
    prefix: LengthPrefix,
}

impl VectorSpec {
    /// Declares a vector whose ceiling is `max_count` elements.
    #[must_use]
    pub const fn new(max_count: u64) -> Self {
        Self {
            max_count,
            prefix: LengthPrefix::for_max_count(max_count),
        }
    }

    /// The ceiling, in elements.
    #[must_use]
    pub const fn max_count(self) -> u64 {
        self.max_count
    }

    /// The length prefix this vector's ceiling implies.
    #[must_use]
    pub const fn prefix(self) -> LengthPrefix {
        self.prefix
    }
}

/// A value that can be written in the presentation language.
pub trait Encode {
    /// Appends `self` to `enc`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VectorTooLong`] if a variable-length vector inside
    /// `self` exceeds the ceiling the draft declares for it.
    fn encode(&self, enc: &mut Encoder) -> Result<()>;
}

/// A value that can be read from the presentation language.
///
/// Not every struct in the draft can implement this: several have a `select`
/// on `Configuration.mode`, which is context the bytes do not carry. Those
/// types take the mode as an explicit argument instead — see
/// [`UpdateValue::decode_with_mode`](crate::structs::UpdateValue::decode_with_mode).
pub trait Decode: Sized {
    /// Reads one `Self` from `dec`, advancing it past the bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the bytes are not a well-formed `Self`. Must
    /// never panic: the input is untrusted.
    fn decode(dec: &mut Decoder<'_>) -> Result<Self>;
}

/// Encodes one value into a fresh byte vector.
///
/// # Errors
///
/// Propagates any [`Error`] from `value`'s [`Encode`] implementation.
pub fn encode<T: Encode + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let mut enc = Encoder::new();
    value.encode(&mut enc)?;
    Ok(enc.into_bytes())
}

/// Decodes one value from exactly `bytes`.
///
/// # Errors
///
/// Returns [`Error::TrailingBytes`] if `bytes` holds more than one value, plus
/// anything `T`'s [`Decode`] implementation reports.
pub fn decode<T: Decode>(bytes: &[u8]) -> Result<T> {
    let mut dec = Decoder::new(bytes);
    let value = T::decode(&mut dec)?;
    dec.finish()?;
    Ok(value)
}

/// A growable buffer of presentation-language bytes.
#[derive(Clone, Debug, Default)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    /// A new, empty encoder.
    #[must_use]
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// A new encoder with room for `capacity` bytes.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    /// Writes a `uint8`.
    pub fn u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    /// Writes a `uint16`, big-endian.
    pub fn u16(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    /// Writes a `uint32`, big-endian.
    pub fn u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    /// Writes a `uint64`, big-endian.
    pub fn u64(&mut self, value: u64) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    /// Writes a fixed-length `opaque x[n]`: the bytes alone, no length prefix.
    ///
    /// The length is part of the type, so it is the caller's job to pass the
    /// right number of bytes — for `opaque opening[Nc]` that means `Nc` bytes
    /// from the cipher suite in force.
    pub fn opaque_fixed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Writes a variable-length `opaque x<0..max>`: length prefix, then bytes.
    ///
    /// # Errors
    ///
    /// [`Error::VectorTooLong`] if `bytes` is longer than `spec`'s ceiling.
    pub fn opaque_vector(&mut self, spec: VectorSpec, bytes: &[u8]) -> Result<()> {
        let count = as_u64(bytes.len());
        self.length(spec, count)?;
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    /// Writes a variable-length vector of encodable elements.
    ///
    /// The prefix is the **element count**, not the byte length — see the
    /// module documentation on §2.1.2.
    ///
    /// # Errors
    ///
    /// [`Error::VectorTooLong`] if `items` is longer than `spec`'s ceiling, plus
    /// anything an element's [`Encode`] implementation reports.
    pub fn vector<T: Encode>(&mut self, spec: VectorSpec, items: &[T]) -> Result<()> {
        let count = as_u64(items.len());
        self.length(spec, count)?;
        for item in items {
            item.encode(self)?;
        }
        Ok(())
    }

    /// Writes an `optional<T>` (§2.1.1): a presence octet, then the value.
    ///
    /// # Errors
    ///
    /// Propagates anything `T`'s [`Encode`] implementation reports.
    pub fn optional<T: Encode>(&mut self, value: Option<&T>) -> Result<()> {
        match value {
            None => {
                self.u8(0);
                Ok(())
            }
            Some(inner) => {
                self.u8(1);
                inner.encode(self)
            }
        }
    }

    /// The bytes written so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Consumes the encoder and returns its bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Writes a length prefix after checking it against the ceiling.
    ///
    /// The `as` casts cannot truncate: [`VectorSpec::new`] derives the prefix
    /// from the ceiling, so `count <= spec.max_count() <= prefix.capacity()`.
    fn length(&mut self, spec: VectorSpec, count: u64) -> Result<()> {
        if count > spec.max_count() {
            return Err(Error::VectorTooLong {
                count,
                max: spec.max_count(),
            });
        }
        match spec.prefix() {
            LengthPrefix::U8 => self.u8(count as u8),
            LengthPrefix::U16 => self.u16(count as u16),
            LengthPrefix::U32 => self.u32(count as u32),
        }
        Ok(())
    }
}

/// A cursor over presentation-language bytes.
///
/// Every read is bounds-checked against the remaining input, and every length
/// prefix is checked against both its declared ceiling and the bytes actually
/// available — a length prefix is a claim by whoever produced the bytes, not a
/// fact.
#[derive(Clone, Debug)]
pub struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// A decoder positioned at the start of `input`.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.pos)
    }

    /// Whether all input has been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Asserts that the input is fully consumed.
    ///
    /// # Errors
    ///
    /// [`Error::TrailingBytes`] if any bytes are left.
    pub fn finish(self) -> Result<()> {
        let remaining = self.remaining();
        if remaining == 0 {
            Ok(())
        } else {
            Err(Error::TrailingBytes { remaining })
        }
    }

    /// Reads a `uint8`.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if the input is exhausted.
    pub fn u8(&mut self) -> Result<u8> {
        let [byte] = self.take_array::<1>()?;
        Ok(byte)
    }

    /// Reads a big-endian `uint16`.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if fewer than two bytes remain.
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take_array::<2>()?))
    }

    /// Reads a big-endian `uint32`.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if fewer than four bytes remain.
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take_array::<4>()?))
    }

    /// Reads a big-endian `uint64`.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if fewer than eight bytes remain.
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take_array::<8>()?))
    }

    /// Reads a fixed-length `opaque x[len]`.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedEof`] if fewer than `len` bytes remain.
    pub fn opaque_fixed(&mut self, len: usize) -> Result<&'a [u8]> {
        self.take(len)
    }

    /// Reads a variable-length `opaque x<0..max>`.
    ///
    /// # Errors
    ///
    /// [`Error::VectorTooLong`] if the prefix exceeds `spec`'s ceiling, or
    /// [`Error::UnexpectedEof`] if it exceeds the bytes available.
    pub fn opaque_vector(&mut self, spec: VectorSpec) -> Result<&'a [u8]> {
        let count = self.length(spec)?;
        let len = usize::try_from(count).map_err(|_| Error::LengthOverflow { value: count })?;
        self.take(len)
    }

    /// Reads a variable-length vector of decodable elements.
    ///
    /// The prefix is the element count (§2.1.2), so the number of bytes consumed
    /// depends on the element type.
    ///
    /// # Errors
    ///
    /// [`Error::VectorTooLong`] if the prefix exceeds `spec`'s ceiling, plus
    /// anything an element's [`Decode`] implementation reports.
    pub fn vector<T: Decode>(&mut self, spec: VectorSpec) -> Result<Vec<T>> {
        let count = self.length(spec)?;
        // Deliberately not `with_capacity(count)`: the count is attacker-chosen
        // and may be orders of magnitude larger than the input that follows it,
        // so allocating up front turns a short message into a memory spike.
        let mut items = Vec::new();
        for _ in 0..count {
            items.push(T::decode(self)?);
        }
        Ok(items)
    }

    /// Reads a variable-length vector whose elements need context to decode.
    ///
    /// Several §13 structures have one: a `BinaryLadderStep`'s proof is `VRF.Np` bytes with
    /// no length prefix of its own, and an `UpdateInfo` needs both `Nc` and the deployment
    /// mode. Their elements cannot implement [`Decode`], because [`Decode`] has nowhere to
    /// put the context — so the count is read here and each element is decoded by `element`.
    ///
    /// # Errors
    ///
    /// [`Error::VectorTooLong`] if the prefix exceeds `spec`'s ceiling, plus anything
    /// `element` reports.
    pub fn vector_with<T>(
        &mut self,
        spec: VectorSpec,
        mut element: impl FnMut(&mut Self) -> Result<T>,
    ) -> Result<Vec<T>> {
        let count = self.length(spec)?;
        // Not `with_capacity`, for the same reason as `vector`: the count is
        // attacker-chosen and need not bear any relation to the bytes that follow.
        let mut items = Vec::new();
        for _ in 0..count {
            items.push(element(self)?);
        }
        Ok(items)
    }

    /// Reads an `optional<T>` (§2.1.1).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPresence`] if the presence octet is not 0 or 1 — the
    /// draft requires rejecting anything else as malformed — plus anything
    /// `T`'s [`Decode`] implementation reports.
    pub fn optional<T: Decode>(&mut self) -> Result<Option<T>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(T::decode(self)?)),
            octet => Err(Error::InvalidPresence { octet }),
        }
    }

    /// Consumes `n` bytes.
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let eof = || Error::UnexpectedEof {
            needed: n,
            remaining: self.remaining(),
        };
        let end = self.pos.checked_add(n).ok_or_else(eof)?;
        let bytes = self.input.get(self.pos..end).ok_or_else(eof)?;
        self.pos = end;
        Ok(bytes)
    }

    /// Consumes exactly `N` bytes into an array.
    fn take_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.take(N)?;
        let mut out = [0_u8; N];
        // Cannot panic: `take` returned exactly `N` bytes or an error.
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Reads and range-checks a length prefix.
    fn length(&mut self, spec: VectorSpec) -> Result<u64> {
        let count = match spec.prefix() {
            LengthPrefix::U8 => u64::from(self.u8()?),
            LengthPrefix::U16 => u64::from(self.u16()?),
            LengthPrefix::U32 => u64::from(self.u32()?),
        };
        if count > spec.max_count() {
            return Err(Error::VectorTooLong {
                count,
                max: spec.max_count(),
            });
        }
        Ok(count)
    }
}

/// Widens a `usize` for comparison against a `u64` ceiling.
///
/// Infallible on every target Rust supports: `usize` is at most 64 bits.
fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

macro_rules! impl_uint_codec {
    ($($ty:ty => $write:ident, $read:ident;)*) => {
        $(
            impl Encode for $ty {
                fn encode(&self, enc: &mut Encoder) -> Result<()> {
                    enc.$write(*self);
                    Ok(())
                }
            }

            impl Decode for $ty {
                fn decode(dec: &mut Decoder<'_>) -> Result<Self> {
                    dec.$read()
                }
            }
        )*
    };
}

impl_uint_codec! {
    u8 => u8, u8;
    u16 => u16, u16;
    u32 => u32, u32;
    u64 => u64, u64;
}

impl<T: Encode> Encode for &T {
    fn encode(&self, enc: &mut Encoder) -> Result<()> {
        (*self).encode(enc)
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "tests fail loudly by panicking; the lints exist to protect \
              production paths that parse untrusted bytes"
)]
mod tests {
    use super::*;
    use alloc::vec;

    /// §2.1.2: the prefix is wide enough to hold the ceiling. `<0..2^8>` is the
    /// interesting one — 256 needs two bytes even though the count fits a byte
    /// most of the time.
    #[test]
    fn prefix_width_follows_ceiling() {
        assert_eq!(LengthPrefix::for_max_count(255), LengthPrefix::U8);
        assert_eq!(LengthPrefix::for_max_count(256), LengthPrefix::U16);
        assert_eq!(LengthPrefix::for_max_count(65535), LengthPrefix::U16);
        assert_eq!(LengthPrefix::for_max_count(65536), LengthPrefix::U32);
        assert_eq!(
            LengthPrefix::for_max_count(u64::from(u32::MAX)),
            LengthPrefix::U32
        );
    }

    #[test]
    fn integers_are_big_endian() {
        let mut enc = Encoder::new();
        enc.u8(0x01);
        enc.u16(0x0203);
        enc.u32(0x0405_0607);
        enc.u64(0x0809_0a0b_0c0d_0e0f);
        let bytes = enc.into_bytes();
        assert_eq!(
            bytes,
            vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f,
            ]
        );

        let mut dec = Decoder::new(&bytes);
        assert_eq!(dec.u8().unwrap(), 0x01);
        assert_eq!(dec.u16().unwrap(), 0x0203);
        assert_eq!(dec.u32().unwrap(), 0x0405_0607);
        assert_eq!(dec.u64().unwrap(), 0x0809_0a0b_0c0d_0e0f);
        dec.finish().unwrap();
    }

    #[test]
    fn opaque_vector_round_trips() {
        const SPEC: VectorSpec = VectorSpec::new(255);

        let mut enc = Encoder::new();
        enc.opaque_vector(SPEC, b"abc").unwrap();
        assert_eq!(enc.as_bytes(), b"\x03abc");

        let mut dec = Decoder::new(enc.as_bytes());
        assert_eq!(dec.opaque_vector(SPEC).unwrap(), b"abc");
        dec.finish().unwrap();
    }

    #[test]
    fn empty_opaque_vector_is_just_a_zero_length() {
        const SPEC: VectorSpec = VectorSpec::new(u32::MAX as u64);

        let mut enc = Encoder::new();
        enc.opaque_vector(SPEC, b"").unwrap();
        assert_eq!(enc.as_bytes(), &[0, 0, 0, 0]);
    }

    #[test]
    fn encoding_over_ceiling_is_rejected() {
        const SPEC: VectorSpec = VectorSpec::new(2);
        let mut enc = Encoder::new();
        assert_eq!(
            enc.opaque_vector(SPEC, b"abc"),
            Err(Error::VectorTooLong { count: 3, max: 2 })
        );
    }

    #[test]
    fn decoding_over_ceiling_is_rejected() {
        // A one-byte prefix can express 3, but the ceiling is 2, so a decoder
        // that only checked the prefix width would over-accept here.
        const SPEC: VectorSpec = VectorSpec::new(2);
        let mut dec = Decoder::new(b"\x03abc");
        assert_eq!(
            dec.opaque_vector(SPEC),
            Err(Error::VectorTooLong { count: 3, max: 2 })
        );
    }

    #[test]
    fn length_prefix_longer_than_input_is_rejected() {
        const SPEC: VectorSpec = VectorSpec::new(255);
        let mut dec = Decoder::new(b"\x05ab");
        assert_eq!(
            dec.opaque_vector(SPEC),
            Err(Error::UnexpectedEof {
                needed: 5,
                remaining: 2
            })
        );
    }

    #[test]
    fn truncated_integer_is_rejected() {
        let mut dec = Decoder::new(&[0x01, 0x02, 0x03]);
        assert_eq!(
            dec.u32(),
            Err(Error::UnexpectedEof {
                needed: 4,
                remaining: 3
            })
        );
    }

    /// The element-count reading of §2.1.2: a one-byte prefix of 3 in front of
    /// three `uint32`s, i.e. twelve bytes of body.
    #[test]
    fn element_vector_prefix_counts_elements_not_bytes() {
        const SPEC: VectorSpec = VectorSpec::new(255);

        let mut enc = Encoder::new();
        enc.vector(SPEC, &[1_u32, 2, 3]).unwrap();
        assert_eq!(
            enc.as_bytes(),
            &[0x03, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3],
            "prefix is the element count, body is 3 * 4 bytes"
        );

        let mut dec = Decoder::new(enc.as_bytes());
        assert_eq!(dec.vector::<u32>(SPEC).unwrap(), vec![1, 2, 3]);
        dec.finish().unwrap();
    }

    /// An inflated element count must fail on running out of input rather than
    /// on allocating for it.
    #[test]
    fn element_vector_with_lying_count_is_rejected() {
        const SPEC: VectorSpec = VectorSpec::new(255);
        let mut dec = Decoder::new(&[0xff, 0, 0, 0, 1]);
        assert!(matches!(
            dec.vector::<u32>(SPEC),
            Err(Error::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn optional_round_trips() {
        let mut enc = Encoder::new();
        enc.optional(None::<&u64>).unwrap();
        enc.optional(Some(&0x2a_u64)).unwrap();
        assert_eq!(enc.as_bytes(), &[0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x2a]);

        let mut dec = Decoder::new(enc.as_bytes());
        assert_eq!(dec.optional::<u64>().unwrap(), None);
        assert_eq!(dec.optional::<u64>().unwrap(), Some(0x2a));
        dec.finish().unwrap();
    }

    /// §2.1.1: "a presence octet with a value other than 0 or 1 MUST be
    /// rejected as malformed."
    #[test]
    fn optional_presence_octet_must_be_zero_or_one() {
        for octet in 2_u8..=255 {
            let bytes = [octet, 0, 0, 0, 0, 0, 0, 0, 0];
            let mut dec = Decoder::new(&bytes);
            assert_eq!(dec.optional::<u64>(), Err(Error::InvalidPresence { octet }));
        }
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        assert_eq!(
            decode::<u16>(&[0x00, 0x01, 0x02]),
            Err(Error::TrailingBytes { remaining: 1 })
        );
        assert_eq!(decode::<u16>(&[0x00, 0x01]), Ok(1));
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail loudly by panicking; the lint protects the parsing paths"
)]
mod error_tests {
    use super::*;
    use alloc::string::ToString as _;

    /// Every error variant renders, and says which numbers it is complaining about.
    ///
    /// Error text is how a verifier explains a rejection, so a `Display` that drops
    /// the interesting value is a real if small defect — and until this test existed,
    /// not one of these arms had ever been executed.
    #[test]
    fn every_error_renders_its_detail() {
        let cases = [
            (
                Error::UnexpectedEof {
                    needed: 4,
                    remaining: 3,
                },
                ["4", "3"],
            ),
            (Error::TrailingBytes { remaining: 7 }, ["7", "trailing"]),
            (
                Error::VectorTooLong {
                    count: 300,
                    max: 255,
                },
                ["300", "255"],
            ),
            (Error::InvalidPresence { octet: 9 }, ["9", "0 or 1"]),
            (
                Error::InvalidEnum {
                    name: "DeploymentMode",
                    value: 4,
                },
                ["4", "DeploymentMode"],
            ),
            (
                Error::HashLength {
                    expected: 32,
                    actual: 31,
                },
                ["32", "31"],
            ),
            (
                Error::LengthOverflow { value: 1 << 40 },
                ["1099511627776", "usize"],
            ),
        ];
        for (error, needles) in cases {
            let rendered = error.to_string();
            assert!(!rendered.is_empty(), "{error:?} rendered empty");
            for needle in needles {
                assert!(
                    rendered.contains(needle),
                    "{error:?} rendered as {rendered:?}, which omits {needle:?}"
                );
            }
        }
    }

    /// Codec errors are leaves: they wrap nothing, so `source` is `None` and a
    /// caller walking the chain terminates.
    #[test]
    fn codec_errors_have_no_source() {
        use core::error::Error as _;
        assert!(Error::TrailingBytes { remaining: 1 }.source().is_none());
    }

    /// The accessors on the vector declaration, which the struct definitions use as
    /// constants and nothing had yet read back.
    #[test]
    fn vector_spec_reports_its_own_shape() {
        const LABEL: VectorSpec = VectorSpec::new(255);
        assert_eq!(LABEL.max_count(), 255);
        assert_eq!(LABEL.prefix(), LengthPrefix::U8);
        assert_eq!(LABEL.prefix().capacity(), 255);

        const HEADS: VectorSpec = VectorSpec::new(256);
        assert_eq!(HEADS.max_count(), 256);
        assert_eq!(HEADS.prefix(), LengthPrefix::U16);
        assert_eq!(HEADS.prefix().capacity(), 65_535);
        assert_eq!(HEADS.prefix().width(), 2);

        // The invariant the type exists to hold: a ceiling always fits its prefix.
        for max in [0_u64, 1, 255, 256, 65_535, 65_536, u32::MAX as u64] {
            let spec = VectorSpec::new(max);
            assert!(
                spec.max_count() <= spec.prefix().capacity(),
                "ceiling {max} does not fit its own prefix"
            );
        }
    }

    /// `LengthOverflow` is only reachable where `usize` is narrower than the length
    /// prefix, i.e. on a 32-bit target. Constructing the error directly is the only
    /// way to cover its rendering on a 64-bit host, and the variant is worth keeping
    /// because the code path that raises it is real on wasm32.
    #[test]
    fn length_overflow_is_a_32_bit_case() {
        let err = Error::LengthOverflow {
            value: u64::from(u32::MAX),
        };
        assert!(err.to_string().contains("does not fit"));
    }

    #[test]
    fn encoder_exposes_its_buffer_both_ways() {
        let mut enc = Encoder::with_capacity(8);
        enc.u16(0x0102);
        assert_eq!(enc.as_bytes(), &[0x01, 0x02]);
        assert_eq!(enc.into_bytes(), alloc::vec![0x01, 0x02]);
        assert!(Encoder::default().as_bytes().is_empty());
    }

    #[test]
    fn decoder_reports_its_position() {
        let mut dec = Decoder::new(&[1, 2, 3, 4]);
        assert_eq!(dec.remaining(), 4);
        assert!(!dec.is_empty());
        dec.u16().unwrap();
        assert_eq!(dec.remaining(), 2);
        dec.u16().unwrap();
        assert!(dec.is_empty());
        dec.finish().unwrap();
    }

    /// `Encode` is implemented for references so a slice of references can be
    /// encoded as a vector; nothing in the protocol has needed it yet.
    #[test]
    fn references_encode_like_their_referents() {
        let direct = encode(&7_u32).unwrap();
        let through_reference = encode(&&7_u32).unwrap();
        assert_eq!(direct, through_reference);
    }
}
