use crate::{BigInt, Fp, FpConfig};
use core::{
    mem::MaybeUninit,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub},
    ptr,
};

/// A field element that may not be in canonical form `[0, p)`.
///
/// All arithmetic uses unchecked operations (fewer cycles on R0VM) that skip
/// the `assert!(result < p)` check. Convert back to [`Fp`] via
/// [`.check()`](Self::check) to assert canonicality, or use
/// [`.reduce()`](Self::reduce) to force reduction.
#[repr(transparent)]
#[derive(educe::Educe)]
#[educe(Copy, Clone)]
pub struct Unreduced<P, const N: usize>(Fp<P, N>);

impl<P, const N: usize> core::fmt::Debug for Unreduced<P, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Unreduced").field(self.0.as_bigint()).finish()
    }
}

impl<P: FpConfig<N>, const N: usize> Unreduced<P, N> {
    #[inline]
    pub const fn from_bigint(b: BigInt<N>) -> Self {
        Self(Fp::from_bigint_unchecked(b))
    }

    /// Wraps a field element for unchecked arithmetic.
    #[inline]
    pub const fn new(fp: Fp<P, N>) -> Self {
        Self(fp)
    }

    /// Returns `true` if this element is zero modulo `p`.
    #[inline]
    pub fn is_zero(&self) -> bool {
        if P::MODULUS.msb_set() {
            // Only 0 and p fit in N limbs.
            self.0.is_zero() || self.0.inner.const_eq(&P::MODULUS)
        } else {
            self.reduce().is_zero()
        }
    }

    /// Asserts the value is in `[0, p)` and returns the inner [`Fp`].
    ///
    /// This is an honest-prover check — `risc0-bigint2` unchecked ops always return
    /// canonical results for honest provers. The assert catches dishonest provers.
    #[inline]
    pub fn check(self) -> Fp<P, N> {
        assert!(self.0.is_valid());
        self.0
    }

    /// Forces reduction to `[0, p)` and returns the inner [`Fp`].
    ///
    /// Prefer [`.check()`](Self::check) when possible — `.reduce()` silently masks
    /// dishonest-prover misbehavior instead of catching it.
    #[inline]
    pub fn reduce(self) -> Fp<P, N> {
        self.0.reduced()
    }

    /// Unchecked modular inverse. Panics in debug builds if `self` is zero.
    #[must_use]
    #[inline]
    pub fn inverse(&self) -> Self {
        debug_assert!(!self.is_zero(), "inverse does not exist for zero");
        unsafe {
            let mut out = MaybeUninit::uninit();
            Fp::inv_into(&self.0, out.as_mut_ptr());
            Self(out.assume_init())
        }
    }
}

impl<P: FpConfig<N>, const N: usize> From<Fp<P, N>> for Unreduced<P, N> {
    #[inline]
    fn from(fp: Fp<P, N>) -> Self {
        Self(fp)
    }
}

// ---------------------------------------------------------------------------
// Operator overloads — unchecked (no canonicality assert).
//
// All take `&self` / `&rhs` to avoid 32-byte copies on rv32im.
// ---------------------------------------------------------------------------

impl<P: FpConfig<N>, const N: usize> Add for &Unreduced<P, N> {
    type Output = Unreduced<P, N>;

    #[inline]
    fn add(self, rhs: Self) -> Unreduced<P, N> {
        unsafe {
            let mut out = MaybeUninit::uninit();
            Fp::add_into(&self.0, &rhs.0, out.as_mut_ptr());
            Unreduced(out.assume_init())
        }
    }
}

impl<P: FpConfig<N>, const N: usize> Sub for &Unreduced<P, N> {
    type Output = Unreduced<P, N>;

    #[inline]
    fn sub(self, rhs: Self) -> Unreduced<P, N> {
        unsafe {
            let mut out = MaybeUninit::uninit();
            Fp::sub_into(&self.0, &rhs.0, out.as_mut_ptr());
            Unreduced(out.assume_init())
        }
    }
}

impl<P: FpConfig<N>, const N: usize> Mul for &Unreduced<P, N> {
    type Output = Unreduced<P, N>;

    #[inline]
    fn mul(self, rhs: Self) -> Unreduced<P, N> {
        unsafe {
            let mut out = MaybeUninit::uninit();
            Fp::mul_into(&self.0, &rhs.0, out.as_mut_ptr());
            Unreduced(out.assume_init())
        }
    }
}

impl<P: FpConfig<N>, const N: usize> Neg for &Unreduced<P, N> {
    type Output = Unreduced<P, N>;

    #[inline]
    fn neg(self) -> Unreduced<P, N> {
        unsafe {
            let mut out = MaybeUninit::uninit();
            Fp::neg_into(&self.0, out.as_mut_ptr());
            Unreduced(out.assume_init())
        }
    }
}

impl<P: FpConfig<N>, const N: usize> AddAssign<&Self> for Unreduced<P, N> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        let ptr = ptr::from_mut(&mut self.0);
        // SAFETY: ptr aliases self as both input and output; the FFI reads before writing.
        unsafe { Fp::add_into(&*ptr, &rhs.0, ptr) };
    }
}

impl<P: FpConfig<N>, const N: usize> AddAssign<&Fp<P, N>> for Unreduced<P, N> {
    #[inline]
    fn add_assign(&mut self, rhs: &Fp<P, N>) {
        let ptr = ptr::from_mut(&mut self.0);
        // SAFETY: ptr aliases self as both input and output; the FFI reads before writing.
        unsafe { Fp::add_into(&*ptr, rhs, ptr) };
    }
}

impl<P: FpConfig<N>, const N: usize> MulAssign<&Self> for Unreduced<P, N> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        let ptr = ptr::from_mut(&mut self.0);
        // SAFETY: ptr aliases self as both input and output; the FFI reads before writing.
        unsafe { Fp::mul_into(&*ptr, &rhs.0, ptr) };
    }
}

impl<P: FpConfig<N>, const N: usize> MulAssign<&Fp<P, N>> for Unreduced<P, N> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Fp<P, N>) {
        let ptr = ptr::from_mut(&mut self.0);
        // SAFETY: ptr aliases self as both input and output; the FFI reads before writing.
        unsafe { Fp::mul_into(&*ptr, rhs, ptr) };
    }
}
