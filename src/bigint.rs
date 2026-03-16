use core::{
    cmp::Ordering,
    ops::{AddAssign, SubAssign},
};

/// A fixed-size `N * 32`-bit integer stored as `N` little-endian `u32` limbs.
#[derive(Copy, Clone, PartialEq, Eq, Hash, bytemuck::TransparentWrapper)]
#[must_use]
#[repr(transparent)]
pub struct BigInt<const N: usize>(pub [u32; N]);

impl<const N: usize> BigInt<N> {
    pub(crate) const LIMB_BITS: usize = u32::BITS as usize;
    pub(crate) const LIMB_BYTES: usize = Self::LIMB_BITS / 8;

    /// The additive identity (all limbs zero).
    pub const ZERO: Self = Self([0u32; N]);

    /// The multiplicative identity (`1` in the lowest limb).
    pub const ONE: Self = Self::from_u32(1);

    /// Creates a [`BigInt`] from a raw limb array.
    #[inline]
    pub const fn new(limbs: [u32; N]) -> Self {
        Self(limbs)
    }

    /// Creates a [`BigInt`] from a single `u32`, placed in the lowest limb.
    #[inline]
    pub const fn from_u32(val: u32) -> Self {
        let mut repr = Self::ZERO;
        repr.0[0] = val;
        repr
    }

    /// Parse a hex string at compile time.
    ///
    /// Requires a `0x` prefix. Underscores are ignored. Values shorter than `N` limbs are
    /// zero-padded in the high limbs.
    ///
    /// ```
    /// # use risc0_crypto::BigInt;
    /// const P: BigInt<8> = BigInt::from_hex("0xffffffff_00000001_ffffffff_ffffffff");
    /// ```
    pub const fn from_hex(s: &str) -> Self {
        let bytes = s.as_bytes();

        assert!(
            bytes.len() >= 2 && bytes[0] == b'0' && bytes[1] == b'x',
            "hex string must start with '0x'"
        );

        // Validate chars upfront to ensure lexical errors precede length overflow errors.
        let mut digit_count: usize = 0;
        let mut i = 2;
        while i < bytes.len() {
            match bytes[i] {
                b'_' => {}
                c if c.is_ascii_hexdigit() => digit_count += 1,
                _ => panic!("invalid hex digit in string"),
            }
            i += 1;
        }

        assert!(digit_count > 0, "expected at least one hex digit after '0x' prefix");

        let mut limbs = [0u32; N];
        let mut limb_idx: usize = 0;
        let mut shift: u32 = 0;

        let mut i = bytes.len();
        while i > 2 {
            i -= 1;
            let val: u8 = match bytes[i] {
                b'0'..=b'9' => bytes[i] - b'0',
                b'a'..=b'f' => bytes[i] - b'a' + 10,
                b'A'..=b'F' => bytes[i] - b'A' + 10,
                _ => continue,
            };

            if limb_idx == N {
                assert!(val == 0, "hex string too large for N limbs");
                continue;
            }

            limbs[limb_idx] |= (val as u32) << shift;
            shift += 4;
            if shift == u32::BITS {
                shift = 0;
                limb_idx += 1;
            }
        }

        Self(limbs)
    }

    /// Parse big-endian bytes into little-endian limbs.
    ///
    /// Inputs shorter than `N * 4` bytes are zero-padded in the high limbs.
    /// Panics if `bytes.len() > N * 4`.
    #[inline]
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() <= N * Self::LIMB_BYTES, "byte slice too large for {N} limbs");

        let mut arr = [0u32; N];
        let chunks = bytes.rchunks_exact(Self::LIMB_BYTES);
        let remainder = chunks.remainder();

        for (dst, chunk) in arr.iter_mut().zip(chunks) {
            *dst = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        let remainder_idx = bytes.len() / Self::LIMB_BYTES;
        // Compiler hint: A remainder implies bytes.len() < N * 4, so remainder_idx < N.
        // This explicit check lets LLVM optimize away the bounds check on arr[remainder_idx].
        if remainder_idx < N {
            match remainder {
                [a, b, c] => arr[remainder_idx] = u32::from_be_bytes([0, *a, *b, *c]),
                [a, b] => arr[remainder_idx] = u32::from_be_bytes([0, 0, *a, *b]),
                [a] => arr[remainder_idx] = *a as u32,
                _ => {}
            }
        }

        Self(arr)
    }

    /// Write little-endian limbs as big-endian bytes into `output`.
    ///
    /// Panics if `output.len() != N * 4`.
    #[inline]
    pub fn write_be_bytes(&self, output: &mut [u8]) {
        assert_eq!(output.len(), N * Self::LIMB_BYTES);
        for (dst, src) in output.rchunks_exact_mut(Self::LIMB_BYTES).zip(self.0.iter()) {
            dst.copy_from_slice(&src.to_be_bytes())
        }
    }

    /// Parse little-endian bytes into limbs (single memcpy on LE targets).
    ///
    /// Panics if `bytes.len() > N * 4`.
    #[cfg(target_endian = "little")]
    #[inline]
    pub fn from_le_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() <= N * Self::LIMB_BYTES, "byte slice too large for {N} limbs");

        let mut arr = [0u32; N];
        bytemuck::cast_slice_mut(&mut arr)[..bytes.len()].copy_from_slice(bytes);
        Self(arr)
    }

    /// View the limbs as a little-endian byte slice (zero-copy on LE targets).
    #[cfg(target_endian = "little")]
    #[inline]
    pub fn as_le_bytes(&self) -> &[u8] {
        bytemuck::cast_slice(&self.0)
    }

    /// Returns `true` if the most significant bit is set.
    #[inline]
    pub const fn msb_set(&self) -> bool {
        self.0[N - 1] >> 31 != 0
    }

    /// Returns `true` if all limbs are zero.
    #[inline]
    pub const fn is_zero(&self) -> bool {
        self.const_eq(&Self::ZERO)
    }

    /// Returns the minimum number of bits needed to represent this value.
    ///
    /// Returns `0` for zero, otherwise `floor(log2(self)) + 1`.
    #[inline]
    pub const fn bit_len(&self) -> u32 {
        let mut i = N;
        while i > 0 {
            i -= 1;
            if self.0[i] != 0 {
                return (i as u32 + 1) * Self::LIMB_BITS as u32 - self.0[i].leading_zeros();
            }
        }
        0
    }

    /// Equality comparison usable in `const` contexts.
    ///
    /// Equivalent to `==` but available in `const fn` where `PartialEq` cannot be used.
    #[inline]
    pub const fn const_eq(&self, other: &Self) -> bool {
        let mut i = 0;
        while i < N {
            if self.0[i] != other.0[i] {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Unsigned less-than comparison, usable in `const` contexts.
    ///
    /// Equivalent to `<` but available in `const fn` where `PartialOrd` cannot be used.
    #[inline]
    pub const fn const_lt(&self, other: &Self) -> bool {
        let mut i = N;
        while i > 0 {
            i -= 1;
            if self.0[i] != other.0[i] {
                return self.0[i] < other.0[i];
            }
        }
        false
    }
}

impl<const N: usize> Default for BigInt<N> {
    #[inline]
    fn default() -> Self {
        Self::ZERO
    }
}

impl<const N: usize> core::fmt::Debug for BigInt<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x")?;
        for &limb in self.0.iter().rev() {
            write!(f, "{limb:08x}")?;
        }
        Ok(())
    }
}

impl<const N: usize> AsRef<[u32; N]> for BigInt<N> {
    #[inline]
    fn as_ref(&self) -> &[u32; N] {
        &self.0
    }
}

impl<const N: usize> From<u32> for BigInt<N> {
    #[inline]
    fn from(val: u32) -> Self {
        Self::from_u32(val)
    }
}

impl<const N: usize> From<[u32; N]> for BigInt<N> {
    #[inline]
    fn from(limbs: [u32; N]) -> Self {
        Self(limbs)
    }
}

impl<const N: usize> From<BigInt<N>> for [u32; N] {
    #[inline]
    fn from(val: BigInt<N>) -> Self {
        val.0
    }
}

impl<const N: usize> PartialOrd for BigInt<N> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize> Ord for BigInt<N> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..N).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
        Ordering::Equal
    }
}

impl<const N: usize> AddAssign<&Self> for BigInt<N> {
    #[inline(always)]
    fn add_assign(&mut self, other: &Self) {
        let mut carry = false;
        for i in 0..N {
            (self.0[i], carry) = self.0[i].carrying_add(other.0[i], carry);
        }
    }
}

impl<const N: usize> SubAssign<&Self> for BigInt<N> {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: &Self) {
        let mut borrow = false;
        for i in 0..N {
            (self.0[i], borrow) = self.0[i].borrowing_sub(rhs.0[i], borrow);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        // 256-bit value (8 limbs)
        let input: [u8; 32] = [
            0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
            0x0D, 0x0E, 0x0F, 0x10,
        ];
        let big = BigInt::<8>::from_be_bytes(&input);
        let mut output = [0u8; 32];
        big.write_be_bytes(&mut output);
        assert_eq!(input, output);
    }

    #[test]
    fn short_input_zero_pads() {
        // 3 bytes into 8 limbs - lands in limb 0, rest zero
        let big = BigInt::<8>::from_be_bytes(&[0x01, 0x02, 0x03]);
        assert_eq!(big.0[0], 0x00_01_02_03);
        for &limb in &big.0[1..] {
            assert_eq!(limb, 0);
        }
    }

    #[test]
    fn empty_input_is_zero() {
        let big = BigInt::<8>::from_be_bytes(&[]);
        assert_eq!(big, BigInt::<8>::ZERO);
    }

    #[test]
    #[should_panic(expected = "byte slice too large")]
    fn panics_on_oversized_input() {
        // 8 limbs = 32 bytes max, give 33
        let _ = BigInt::<8>::from_be_bytes(&[0u8; 33]);
    }

    #[test]
    fn from_hex() {
        // multi-limb parsing, limb order
        assert_eq!(BigInt::<2>::from_hex("0xdeadbeef12345678").0, [0x12345678, 0xdeadbeef]);
        // short value zero-pads high limbs
        assert_eq!(BigInt::<8>::from_hex("0x1"), BigInt::<8>::from_u32(1));
        // underscores are ignored
        assert_eq!(
            BigInt::<2>::from_hex("0xdead_beef_1234_5678"),
            BigInt::<2>::from_hex("0xdeadbeef12345678"),
        );
        // agrees with from_be_bytes
        assert_eq!(
            BigInt::<2>::from_hex("0xdeadbeef12345678"),
            BigInt::<2>::from_be_bytes(&[0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 0x56, 0x78]),
        );
        // leading zeros don't overflow
        assert_eq!(BigInt::<1>::from_hex("0x000000ff").0, [0xff]);
    }

    #[test]
    #[should_panic(expected = "hex string too large")]
    fn from_hex_overflow() {
        let _ = BigInt::<1>::from_hex("0x1ffffffff");
    }

    #[test]
    #[should_panic(expected = "invalid hex digit")]
    fn from_hex_invalid_char() {
        let _ = BigInt::<1>::from_hex("0xgg01ff");
    }

    #[test]
    #[should_panic(expected = "expected at least one hex digit")]
    fn from_hex_bare_prefix() {
        let _ = BigInt::<1>::from_hex("0x");
    }

    #[test]
    fn is_zero() {
        assert!(BigInt::<8>::ZERO.is_zero());
        assert!(!BigInt::<8>::from_u32(1).is_zero());
        assert!(!BigInt::<8>::from_hex("0x10000000000000000").is_zero());
    }

    #[test]
    fn bit_len() {
        assert_eq!(BigInt::<8>::ZERO.bit_len(), 0);
        assert_eq!(BigInt::<8>::ONE.bit_len(), 1);
        assert_eq!(BigInt::<8>::from_u32(2).bit_len(), 2);
        assert_eq!(BigInt::<8>::from_u32(3).bit_len(), 2);
        assert_eq!(BigInt::<8>::from_u32(0xff).bit_len(), 8);
        assert_eq!(BigInt::<8>::from_u32(0x100).bit_len(), 9);
        assert_eq!(BigInt::<8>::from_u32(u32::MAX).bit_len(), 32);
        // multi-limb: 0x1_00000000 = 2³²
        assert_eq!(BigInt::<8>::from_hex("0x100000000").bit_len(), 33);
        // 256-bit value (secp256k1 group order)
        let n = BigInt::<8>::from_hex(
            "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        );
        assert_eq!(n.bit_len(), 256);
    }

    #[test]
    fn ordering() {
        let a = BigInt::<8>::from_u32(5);
        let b = BigInt::<8>::from_u32(10);

        // const_lt (for const contexts)
        assert!(a.const_lt(&b));
        assert!(!b.const_lt(&a));
        assert!(!a.const_lt(&a));

        // Ord / PartialOrd operators
        assert!(a < b);
        assert!(b > a);
        assert!(a <= a);
        assert!(a >= a);
        assert_eq!(a.cmp(&b), Ordering::Less);

        // high-limb difference dominates
        let lo = BigInt::<2>::from_hex("0x00000001ffffffff");
        let hi = BigInt::<2>::from_hex("0x0000000200000000");
        assert!(lo < hi);
        assert!(lo.const_lt(&hi));
        assert!(!hi.const_lt(&lo));
    }
}
