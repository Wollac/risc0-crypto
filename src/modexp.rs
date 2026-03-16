use crate::BigInt;
use risc0_bigint2::field::{modmul_256, modmul_384, modmul_4096, unchecked};

mod private {
    pub trait Sealed {}
    impl Sealed for [u32; 8] {}
    impl Sealed for [u32; 12] {}
    impl Sealed for [u32; 128] {}
}

/// Bit-level access to an exponent value.
pub trait BitAccess {
    /// Returns the number of significant bits (i.e. `1 + floor(log2(self))`), or 0 for zero.
    fn bits(&self) -> usize;

    /// Returns `true` if bit `i` is set, where `i = 0` is the LSB.
    fn bit(&self, i: usize) -> bool;
}

impl<const N: usize> BitAccess for BigInt<N> {
    #[inline]
    fn bits(&self) -> usize {
        self.bit_len() as usize
    }

    #[inline]
    fn bit(&self, i: usize) -> bool {
        let limb = i / Self::LIMB_BITS;
        limb < N && self.0[limb] & (1 << (i % Self::LIMB_BITS)) != 0
    }
}

/// Dispatches modular multiplication by array width.
///
/// Sealed - cannot be implemented outside this crate.
pub trait ModMul: private::Sealed {
    #[doc(hidden)]
    fn modmul(a: &Self, b: &Self, m: &Self, r: &mut Self);
    #[doc(hidden)]
    fn modmul_unchecked(a: &Self, b: &Self, m: &Self, r: &mut Self);
}

impl ModMul for [u32; 8] {
    #[inline]
    fn modmul(a: &Self, b: &Self, m: &Self, r: &mut Self) {
        modmul_256(a, b, m, r);
    }
    #[inline]
    fn modmul_unchecked(a: &Self, b: &Self, m: &Self, r: &mut Self) {
        unchecked::modmul_256(a, b, m, r);
    }
}

impl ModMul for [u32; 12] {
    #[inline]
    fn modmul(a: &Self, b: &Self, m: &Self, r: &mut Self) {
        modmul_384(a, b, m, r);
    }
    #[inline]
    fn modmul_unchecked(a: &Self, b: &Self, m: &Self, r: &mut Self) {
        unchecked::modmul_384(a, b, m, r);
    }
}

impl ModMul for [u32; 128] {
    #[inline]
    fn modmul(a: &Self, b: &Self, m: &Self, r: &mut Self) {
        modmul_4096(a, b, m, r);
    }
    #[inline]
    fn modmul_unchecked(a: &Self, b: &Self, m: &Self, r: &mut Self) {
        unchecked::modmul_4096(a, b, m, r);
    }
}

/// Computes `base^exp mod modulus` using left-to-right square-and-multiply.
///
/// Returns [`BigInt::ZERO`] when `modulus` is one or [`BigInt::ONE`] when `exp` is zero.
// TODO: a 4-bit sliding window would save ~50 multiplications per 256-bit exponent
pub fn modexp<const N: usize>(
    base: &BigInt<N>,
    exp: &(impl BitAccess + ?Sized),
    modulus: &BigInt<N>,
) -> BigInt<N>
where
    [u32; N]: ModMul,
{
    if modulus == &BigInt::ONE {
        return BigInt::ZERO;
    }
    let n = exp.bits();
    if n == 0 {
        return BigInt::ONE;
    }
    if n == 1 {
        // single checked modmul(base, 1) to reduce base into [0, modulus)
        let mut r = BigInt::ZERO;
        <[u32; N]>::modmul(&base.0, &BigInt::ONE.0, &modulus.0, &mut r.0);
        return r;
    }

    // double-buffered: swap references (pointer-sized) instead of values
    let mut t1 = *base;
    let mut t2 = BigInt::ZERO;
    let mut cur = &mut t1;
    let mut buf = &mut t2;

    // start from second-highest bit (MSB is implicitly handled by initializing cur = base)
    for i in (0..n - 1).rev() {
        // next <- curr²
        <[u32; N]>::modmul_unchecked(&cur.0, &cur.0, &modulus.0, &mut buf.0);

        if exp.bit(i) {
            // curr <- next * base
            <[u32; N]>::modmul_unchecked(&buf.0, &base.0, &modulus.0, &mut cur.0);
        } else {
            // curr <- next
            core::mem::swap(&mut cur, &mut buf);
        }
    }

    // verify result is canonical (honest prover check)
    assert!(*cur < *modulus);

    *cur
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn bigint_bit_access_bit() {
        let v = BigInt::<8>::from_u32(0b1010);
        assert!(!v.bit(0));
        assert!(v.bit(1));
        assert!(!v.bit(2));
        assert!(v.bit(3));
        assert!(!v.bit(4));
        // out of range
        assert!(!v.bit(256));
    }

    #[rstest]
    #[case::modulus_one(5, 3, 1, 0)]
    #[case::modulus_one_exp_zero(5, 0, 1, 0)]
    #[case::exp_zero(42, 0, 7, 1)]
    #[case::zero_to_zero(0, 0, 7, 1)]
    #[case::exp_one(5, 1, 7, 5)]
    #[case::exp_one_reduces(10, 1, 7, 3)]
    #[case::base_exceeds_modulus(10, 2, 7, 2)]
    fn modexp_small(#[case] base: u32, #[case] exp: u32, #[case] m: u32, #[case] expected: u32) {
        let exp: BigInt<1> = BigInt::from_u32(exp);
        assert_eq!(modexp::<8>(&base.into(), &exp, &m.into()), expected.into());
    }

    #[test]
    fn fermats_little_theorem_256bit() {
        // a^(p-1) = 1 mod p for secp256k1 field prime
        let p = BigInt::<8>::from_hex(
            "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        );
        let base = BigInt::<8>::from_u32(2);
        let exp = BigInt::<8>::from_hex(
            "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E",
        );
        assert_eq!(modexp(&base, &exp, &p), BigInt::ONE);
    }
}
