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
/// Arithmetic on `Unreduced` skips the `assert!(result < p)` canonicality check that [`Fp`]
/// performs after every operation. Convert back to [`Fp`] via [`check`](Self::check) to
/// assert canonicality, or [`reduce`](Self::reduce) to force reduction.
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

    /// Raw limb equality. Does NOT reduce first - two values representing the same field
    /// element may compare unequal if either is unreduced. Use [`check_is_eq`](Self::check_is_eq)
    /// for field equality.
    #[inline]
    pub fn raw_eq(&self, other: &Self) -> bool {
        self.as_bigint() == other.as_bigint()
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

impl<P: FpConfig<N>, const N: usize> Unreduced<P, N> {
    /// Returns `true` if the value is in `[0, p)` (i.e. already a valid [`Fp`]).
    #[inline(always)]
    pub const fn is_canonical(&self) -> bool {
        self.inner.const_lt(&P::MODULUS)
    }

    /// Returns `true` if this element represents the field zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        if P::MODULUS.msb_set() {
            // Only 0 and p fit in N limbs.
            self.inner.is_zero() || self.inner.const_eq(&P::MODULUS)
        } else {
            self.reduce().is_zero()
        }
    }

    /// Returns `true` if both represent the same field element. When unequal, asserts the larger
    /// value is canonical - panics if a dishonest prover produced an unreduced result.
    #[inline]
    pub fn check_is_eq(&self, other: &Self) -> bool {
        match self.inner.cmp(&other.inner) {
            Ordering::Equal => true,
            Ordering::Less => {
                assert!(other.is_canonical());
                false
            }
            Ordering::Greater => {
                assert!(self.is_canonical());
                false
            }
        }
    }

    /// Asserts the value is in `[0, p)` and returns an [`Fp`]. Panics otherwise.
    #[inline(always)]
    pub const fn check(self) -> Fp<P, N> {
        assert!(self.is_canonical());
        Fp { inner: self.inner, _marker: PhantomData }
    }

    /// Asserts the value is in `[0, p)` and returns a reference to the value as [`Fp`].
    /// Panics otherwise. Zero-cost - no copy, just a pointer cast.
    #[inline(always)]
    pub fn check_ref(&self) -> &Fp<P, N> {
        assert!(self.is_canonical());
        // SAFETY: Unreduced<P, N> and Fp<P, N> are both #[repr(transparent)] over BigInt<N>
        const {
            assert!(size_of::<Self>() == size_of::<Fp<P, N>>());
            assert!(align_of::<Self>() == align_of::<Fp<P, N>>());
        }
        unsafe { &*ptr::from_ref(self).cast() }
    }

    /// Forces reduction to `[0, p)` and returns an [`Fp`].
    ///
    /// Prefer [`check`](Self::check) when possible: [`reduce`](Self::reduce) silently fixes
    /// non-canonical values instead of catching them.
    #[inline]
    pub fn reduce(mut self) -> Fp<P, N> {
        self.reduce_in_place();
        Fp { inner: self.inner, _marker: PhantomData }
    }

    /// Forces reduction to `[0, p)` in place.
    #[inline(always)]
    fn reduce_in_place(&mut self) {
        if self.is_canonical() {
            return;
        }
        // If MSB of modulus is set, 2p overflows N limbs, so a >= p implies a in [p, 2p).
        if P::MODULUS.msb_set() {
            self.inner -= &P::MODULUS;
            return;
        }
        // Adding zero forces reduction via the modular-add syscall
        *self += &P::ZERO;
        assert!(self.is_canonical());
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
        debug_assert!(!self.is_zero(), "inverse does not exist for zero");
        // SAFETY: out is fully written by fp_inv before assume_init.
        unsafe {
            let mut out = MaybeUninit::uninit();
            P::fp_inv(self, out.as_mut_ptr());
            out.assume_init()
        }
    }
}

// --- Unchecked operator impls ---
//
// Two performance-critical patterns, each hand-written:
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
    fn canonicality() {
        assert!(uf(6).is_canonical());
        assert!(!uf(7).is_canonical());
        assert!(!uf(10).is_canonical());

        assert_eq!(uf(3).check(), F::from_u32(3));
        assert_eq!(uf(10).reduce(), F::from_u32(3));
    }

    #[test]
    #[should_panic]
    fn check_rejects_non_canonical() {
        let _ = uf(10).check();
    }

    #[test]
    fn is_zero() {
        assert!(uf(0).is_zero());
        assert!(uf(7).is_zero()); // p mod p = 0
        assert!(!uf(1).is_zero());
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
