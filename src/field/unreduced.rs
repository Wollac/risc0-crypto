use crate::{BigInt, Fp, FpConfig};
use core::{
    cmp::Ordering,
    marker::PhantomData,
    mem::MaybeUninit,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    ptr,
};

/// A field element that may not be in canonical form `[0, p)`.
///
/// Arithmetic on `Unreduced` is always sound - non-canonical inputs produce correct field results.
/// To extract a canonical [`Fp`] value, there are two strategies:
/// - [`check`](Self::check) - asserts the value is already in `[0, p)`, panics otherwise
/// - [`reduce`](Self::reduce) - forces the value into `[0, p)`, always succeeds
///
/// The same check-vs-reduce choice applies to comparisons (which also "leave" the struct by
/// producing a field-semantic `bool`):
/// - [`check_is_eq`](Self::check_is_eq) - asserts both values are canonical when they differ
/// - `self.reduce() == other.reduce()` - reduce-style equality
///
/// `PartialEq` / `Eq` are deliberately not implemented because the right comparison depends on
/// context.
#[derive(educe::Educe, bytemuck::TransparentWrapper)]
#[educe(Copy, Clone)]
#[must_use]
#[repr(transparent)]
#[transparent(BigInt<N>)]
pub struct Unreduced<P, const N: usize> {
    inner: BigInt<N>,
    _marker: PhantomData<P>,
}

impl<P, const N: usize> Unreduced<P, N> {
    /// Creates an `Unreduced` from a raw [`BigInt`].
    #[inline]
    pub const fn from_bigint(b: BigInt<N>) -> Self {
        Self { inner: b, _marker: PhantomData }
    }

    /// Returns a reference to the underlying [`BigInt`].
    #[inline]
    pub const fn as_bigint(&self) -> &BigInt<N> {
        &self.inner
    }

    /// Returns the underlying [`BigInt`] by value.
    #[inline]
    pub const fn to_bigint(self) -> BigInt<N> {
        self.inner
    }

    /// Raw integer equality, not field equality. May give false negatives.
    #[inline]
    pub(crate) fn raw_eq(&self, other: &Self) -> bool {
        self.as_bigint() == other.as_bigint()
    }
}

impl<P: FpConfig<N>, const N: usize> Unreduced<P, N> {
    /// Returns `true` if the value is in `[0, p)` (i.e. already a valid [`Fp`]).
    #[inline(always)]
    pub const fn is_canonical(&self) -> bool {
        self.inner.const_lt(&P::MODULUS)
    }

    /// Asserts the value is in `[0, p)` and returns an [`Fp`]. Panics otherwise.
    ///
    /// Use when the value is expected to be canonical. For values that may legitimately be
    /// non-canonical (e.g. cross-field reduction), use [`reduce`](Self::reduce) instead.
    #[inline(always)]
    pub const fn check(self) -> Fp<P, N> {
        assert!(self.is_canonical(), "non-canonical field element");
        Fp { inner: self.inner, _marker: PhantomData }
    }

    /// Asserts the value is in `[0, p)` and returns a reference to the value as [`Fp`]. Panics
    /// otherwise. Zero-cost - no copy, just a pointer cast.
    #[inline(always)]
    pub fn check_ref(&self) -> &Fp<P, N> {
        assert!(self.is_canonical(), "non-canonical field element");
        // SAFETY: caller asserted is_canonical
        unsafe { self.as_fp_ref_unchecked() }
    }

    /// Field equality using check semantics. Returns `true` if the raw integers are equal.
    /// When they differ, asserts canonicality and returns `false` - panics if either value is
    /// non-canonical. Only the larger value is explicitly checked: if the smaller were `>= p`,
    /// the larger would also be `> p`, so a single check suffices.
    #[inline]
    pub fn check_is_eq(&self, other: &Self) -> bool {
        match self.inner.cmp(&other.inner) {
            Ordering::Equal => true,
            Ordering::Less => {
                assert!(other.is_canonical(), "non-canonical field element");
                false
            }
            Ordering::Greater => {
                assert!(self.is_canonical(), "non-canonical field element");
                false
            }
        }
    }

    /// Forces reduction to `[0, p)` by value and returns an [`Fp`]. Always succeeds.
    ///
    /// Use when the value may legitimately be non-canonical, e.g. reducing a base field value
    /// into a scalar field for ECDSA, or normalizing external input. When the value is expected
    /// to already be canonical, prefer [`check`](Self::check) which makes that assumption
    /// explicit.
    #[inline(always)]
    pub fn reduce(mut self) -> Fp<P, N> {
        *self.reduce_in_place()
    }

    /// Forces reduction to `[0, p)` in place and returns a reference to the value as [`Fp`].
    /// Always succeeds.
    #[inline]
    pub fn reduce_in_place(&mut self) -> &Fp<P, N> {
        if !self.is_canonical() {
            if P::MODULUS.msb_set() {
                // 2p overflows N limbs, so a >= p implies a in [p, 2p) - single subtraction
                self.inner -= &P::MODULUS;
            } else {
                P::fp_reduce(&mut self.inner);
            }
        }
        // SAFETY: already canonical, or made so by subtraction (MSB path) / fp_reduce
        unsafe { self.as_fp_ref_unchecked() }
    }

    /// Reinterprets `&self` as `&Fp` without checking canonicality.
    ///
    /// # Safety
    ///
    /// The caller must ensure the value is in `[0, p)`.
    #[inline(always)]
    const unsafe fn as_fp_ref_unchecked(&self) -> &Fp<P, N> {
        const {
            assert!(size_of::<Self>() == size_of::<Fp<P, N>>());
            assert!(align_of::<Self>() == align_of::<Fp<P, N>>());
        }
        unsafe { &*ptr::from_ref(self).cast() }
    }

    /// Computes `-self mod p` in place.
    #[inline]
    pub fn neg_in_place(&mut self) {
        let ptr = ptr::from_mut(self);
        // SAFETY: a (ptr) aliases out (ptr) per FpConfig's contract.
        unsafe { P::fp_neg(ptr, ptr) };
    }

    /// Computes `self⁻¹ mod p`. Computing the inverse of zero is undefined behavior.
    #[inline]
    pub fn inverse(&self) -> Self {
        debug_assert!(!(*self).reduce().is_zero(), "inverse does not exist for zero");
        // SAFETY: out is fully written by fp_inv before assume_init.
        unsafe {
            let mut out = MaybeUninit::uninit();
            P::fp_inv(self, out.as_mut_ptr());
            out.assume_init()
        }
    }
}

impl<P, const N: usize> core::fmt::Debug for Unreduced<P, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Unreduced").field(self.as_bigint()).finish()
    }
}

impl<P, const N: usize> From<BigInt<N>> for Unreduced<P, N> {
    #[inline]
    fn from(b: BigInt<N>) -> Self {
        Self::from_bigint(b)
    }
}

impl<P, const N: usize> From<Fp<P, N>> for Unreduced<P, N> {
    #[inline]
    fn from(fp: Fp<P, N>) -> Self {
        Self::from_bigint(fp.inner)
    }
}

impl<P, const N: usize> AsRef<Self> for Unreduced<P, N> {
    #[inline]
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<P, const N: usize> AsRef<Unreduced<P, N>> for Fp<P, N> {
    #[inline]
    fn as_ref(&self) -> &Unreduced<P, N> {
        self.as_unreduced()
    }
}

// --- Operator impls ---
//
// two performance-critical patterns, each hand-written:
// - &ref Op &ref: MaybeUninit output, no copies
// - val OpAssign &ref: aliased input/output pointer, zero allocation

impl<P: FpConfig<N>, const N: usize, T: AsRef<Unreduced<P, N>>> Add<&T> for &Unreduced<P, N> {
    type Output = Unreduced<P, N>;
    #[inline]
    fn add(self, rhs: &T) -> Unreduced<P, N> {
        // SAFETY: out is fully written by fp_add before assume_init.
        unsafe {
            let mut out = MaybeUninit::uninit();
            P::fp_add(self, rhs.as_ref(), out.as_mut_ptr());
            out.assume_init()
        }
    }
}

impl<P: FpConfig<N>, const N: usize, T: AsRef<Unreduced<P, N>>> Sub<&T> for &Unreduced<P, N> {
    type Output = Unreduced<P, N>;
    #[inline]
    fn sub(self, rhs: &T) -> Unreduced<P, N> {
        // SAFETY: out is fully written by fp_sub before assume_init.
        unsafe {
            let mut out = MaybeUninit::uninit();
            P::fp_sub(self, rhs.as_ref(), out.as_mut_ptr());
            out.assume_init()
        }
    }
}

impl<P: FpConfig<N>, const N: usize, T: AsRef<Unreduced<P, N>>> Mul<&T> for &Unreduced<P, N> {
    type Output = Unreduced<P, N>;
    #[inline]
    fn mul(self, rhs: &T) -> Unreduced<P, N> {
        // SAFETY: out is fully written by fp_mul before assume_init.
        unsafe {
            let mut out = MaybeUninit::uninit();
            P::fp_mul(self, rhs.as_ref(), out.as_mut_ptr());
            out.assume_init()
        }
    }
}

impl<P: FpConfig<N>, const N: usize> Neg for &Unreduced<P, N> {
    type Output = Unreduced<P, N>;
    #[inline]
    fn neg(self) -> Unreduced<P, N> {
        // SAFETY: out is fully written by fp_neg before assume_init.
        unsafe {
            let mut out = MaybeUninit::uninit();
            P::fp_neg(self, out.as_mut_ptr());
            out.assume_init()
        }
    }
}

impl<P: FpConfig<N>, const N: usize, T: AsRef<Self>> AddAssign<&T> for Unreduced<P, N> {
    #[inline]
    fn add_assign(&mut self, rhs: &T) {
        let ptr = ptr::from_mut(self);
        // SAFETY: a (ptr) aliases out (ptr) per FpConfig's contract.
        unsafe { P::fp_add(ptr, rhs.as_ref(), ptr) };
    }
}

impl<P: FpConfig<N>, const N: usize, T: AsRef<Self>> SubAssign<&T> for Unreduced<P, N> {
    #[inline]
    fn sub_assign(&mut self, rhs: &T) {
        let ptr = ptr::from_mut(self);
        // SAFETY: a (ptr) aliases out (ptr) per FpConfig's contract.
        unsafe { P::fp_sub(ptr, rhs.as_ref(), ptr) };
    }
}

impl<P: FpConfig<N>, const N: usize, T: AsRef<Self>> MulAssign<&T> for Unreduced<P, N> {
    #[inline]
    fn mul_assign(&mut self, rhs: &T) {
        let ptr = ptr::from_mut(self);
        // SAFETY: a (ptr) aliases out (ptr) per FpConfig's contract.
        unsafe { P::fp_mul(ptr, rhs.as_ref(), ptr) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Fp256, R0FieldConfig};

    // Test field: F_7 (arbitrary small prime, independent of any curve).
    enum P {}
    impl R0FieldConfig<8> for P {
        const MODULUS: BigInt<8> = BigInt::from_u32(7);
    }

    type F = Fp256<P>;

    fn uf(v: u32) -> Unreduced<P, 8> {
        Unreduced::from_bigint(BigInt::from_u32(v))
    }

    #[test]
    fn check() {
        assert!(uf(6).is_canonical());
        assert!(!uf(7).is_canonical());
        assert!(!uf(10).is_canonical());

        assert_eq!(uf(3).check(), F::from_u32(3));
        assert_eq!(*uf(3).check_ref(), F::from_u32(3));
        assert!(uf(3).check_is_eq(&uf(3)));
        assert!(!uf(3).check_is_eq(&uf(5)));
        assert!(uf(10).check_is_eq(&uf(10))); // equal non-canonical
    }

    #[test]
    #[should_panic]
    fn check_rejects_non_canonical() {
        let _ = uf(10).check();
    }

    #[test]
    #[should_panic]
    fn check_ref_rejects_non_canonical() {
        let _ = uf(10).check_ref();
    }

    #[test]
    fn reduce() {
        assert_eq!(uf(10).reduce(), F::from_u32(3));
        assert_eq!(uf(3).reduce(), F::from_u32(3)); // already canonical

        let mut v = uf(10);
        assert_eq!(*v.reduce_in_place(), F::from_u32(3));
        assert!(v.is_canonical());
    }

    #[test]
    fn ops() {
        assert_eq!((&uf(3) + &uf(5)).check(), F::from_u32(1));
        assert_eq!((&uf(3) * &uf(5)).check(), F::from_u32(1));
        assert_eq!((&uf(5) - &uf(3)).check(), F::from_u32(2));
        assert_eq!((-&uf(3)).check(), F::from_u32(4));
        assert_eq!(uf(3).inverse().check(), F::from_u32(5));
    }

    #[test]
    fn assign_ops() {
        let two = F::from_u32(2);
        let mut r = uf(3);
        r += &two;
        assert_eq!(r.check(), F::from_u32(5));
        let mut r = uf(3);
        r -= &two;
        assert_eq!(r.check(), F::from_u32(1));
        let mut r = uf(3);
        r *= &two;
        assert_eq!(r.check(), F::from_u32(6));
        let mut r = uf(3);
        r.neg_in_place();
        assert_eq!(r.check(), F::from_u32(4)); // -3 mod 7
    }

    #[test]
    fn non_canonical_input() {
        // 10 in limbs = 3 mod 7, not canonical
        let three = uf(10);
        let two = F::from_u32(2);

        assert_eq!((&three + &two).check(), F::from_u32(5));
        assert_eq!((&three * &two).check(), F::from_u32(6));
        assert_eq!((&three - &two).check(), F::from_u32(1));
    }
}
