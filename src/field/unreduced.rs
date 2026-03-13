use crate::{BigInt, Fp, FpConfig};
use core::{
    mem::MaybeUninit,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    ptr,
};

/// A field element that may not be in canonical form `[0, p)`.
///
/// Arithmetic on `Unreduced` skips the `assert!(result < p)` canonicality check that [`Fp`]
/// performs after every operation. Convert back to [`Fp`] via [`check`](Self::check) to
/// assert canonicality, or [`reduce`](Self::reduce) to force reduction.
#[derive(educe::Educe)]
#[educe(Copy, Clone)]
#[must_use]
#[repr(transparent)]
pub struct Unreduced<P, const N: usize>(Fp<P, N>);

// SAFETY: Unreduced is #[repr(transparent)] over Fp, which is #[repr(transparent)] over BigInt.
// The only other field (PhantomData<P> inside Fp) is a ZST.
unsafe impl<P, const N: usize> bytemuck::TransparentWrapper<BigInt<N>> for Unreduced<P, N> {}

impl<P, const N: usize> core::fmt::Debug for Unreduced<P, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Unreduced").field(self.as_bigint()).finish()
    }
}

impl<P, const N: usize> Unreduced<P, N> {
    /// Wraps a canonical [`Fp`] for unchecked arithmetic.
    #[inline]
    pub const fn new(fp: Fp<P, N>) -> Self {
        Self(fp)
    }

    /// Creates an `Unreduced` from a raw [`BigInt`].
    #[inline]
    pub const fn from_bigint(b: BigInt<N>) -> Self {
        Self(Fp::from_bigint_unchecked(b))
    }

    /// Returns a reference to the underlying [`BigInt`].
    #[inline]
    pub const fn as_bigint(&self) -> &BigInt<N> {
        &self.0.inner
    }

    /// Returns a mutable reference to the underlying [`BigInt`].
    #[inline]
    pub const fn as_bigint_mut(&mut self) -> &mut BigInt<N> {
        &mut self.0.inner
    }
}

impl<P, const N: usize> From<Fp<P, N>> for Unreduced<P, N> {
    #[inline]
    fn from(fp: Fp<P, N>) -> Self {
        Self(fp)
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
    /// Returns `true` if this element represents the field zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        if P::MODULUS.msb_set() {
            // Only 0 and p fit in N limbs.
            self.0.is_zero() || self.0.as_bigint().const_eq(&P::MODULUS)
        } else {
            self.reduce().is_zero()
        }
    }

    /// Asserts the value is in `[0, p)` and returns the inner [`Fp`]. Panics otherwise.
    #[inline]
    pub fn check(self) -> Fp<P, N> {
        assert!(self.0.is_valid());
        self.0
    }

    /// Forces reduction to `[0, p)` and returns the inner [`Fp`].
    ///
    /// Prefer [`check`](Self::check) when possible: [`reduce`](Self::reduce) silently fixes
    /// non-canonical values instead of catching them.
    #[inline]
    pub fn reduce(mut self) -> Fp<P, N> {
        self.reduce_in_place();
        self.0
    }

    /// Forces reduction to `[0, p)` in place, returning a reference to the inner [`Fp`].
    ///
    /// Prefer [`check`](Self::check) when possible: [`reduce_in_place`](Self::reduce_in_place)
    /// silently fixes non-canonical values instead of catching them.
    #[inline(always)]
    pub fn reduce_in_place(&mut self) -> &Fp<P, N> {
        if self.0.is_valid() {
            return &self.0;
        }
        // If MSB of modulus is set, 2p overflows N limbs, so a >= p implies a in [p, 2p).
        if P::MODULUS.msb_set() {
            self.0.inner -= &P::MODULUS;
            return &self.0;
        }
        // Adding zero forces reduction via the modular-add syscall
        *self += &P::ZERO;
        assert!(self.0.is_valid());
        &self.0
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

// ---------------------------------------------------------------------------
// Primitive operator impls.
//
// Two performance-critical patterns, each hand-written:
// - &ref Op &ref: MaybeUninit output, no copies
// - val OpAssign &ref: aliased input/output pointer, zero allocation
// ---------------------------------------------------------------------------

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
    use bytemuck::TransparentWrapper;

    /// Exercises the runtime size/align assertions inside `wrap_ref` and `peel_ref`.
    /// Catches accidental layout changes (e.g. adding a non-ZST field to Unreduced or Fp).
    #[test]
    fn transparent_wrapper_layout() {
        let b = BigInt::<8>::from_u32(42);
        let u: &Unreduced<crate::curves::secp256k1::FqConfig, 8> = Unreduced::wrap_ref(&b);
        let roundtrip: &BigInt<8> = Unreduced::peel_ref(u);
        assert_eq!(*roundtrip, b);
    }
}
