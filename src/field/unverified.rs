use crate::{
    BigInt, BitAccess, Fp,
    field::{FieldConfig, FieldOps as _},
};
use core::{
    cmp::Ordering,
    marker::PhantomData,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

/// A field element resulting from an under-constrained VM operation.
///
/// The prover claims this value is strictly in `[0, p)`, but it has not yet been verified.
/// This type serves as a security boundary: it allows chaining high-performance under-constrained
/// arithmetic, but forces explicit verification before the value can be trusted as a canonical
/// [`Fp`].
///
/// # Arithmetic and Reduction
///
/// Arithmetic on `UnverifiedFp` correctly handles redundant representations (i.e., inputs >= `p`
/// still produce mathematically correct results modulo `p`).
///
/// To extract a canonical [`Fp`], you must cross the verification boundary:
/// - Use [`check()`](Self::check) if the value *should* be canonical. This asserts the value is `<
///   p` and panics if a malicious prover lied.
/// - Use [`Fp::reduce_from_bigint`] if the value is legitimately out of bounds and requires
///   mathematical reduction (e.g., parsing oversized byte arrays).
///
/// # Comparisons
///
/// `PartialEq` / `Eq` are not implemented. Use [`check_is_eq`](Self::check_is_eq) instead.
#[derive(educe::Educe, bytemuck::TransparentWrapper)]
#[educe(Copy, Clone)]
#[must_use]
#[repr(transparent)]
#[transparent(BigInt<N>)]
pub struct UnverifiedFp<P, const N: usize> {
    inner: BigInt<N>,
    _marker: PhantomData<P>,
}

impl<P, const N: usize> UnverifiedFp<P, N> {
    /// Creates an `UnverifiedFp` from a raw [`BigInt`].
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

impl<P: FieldConfig<N>, const N: usize> UnverifiedFp<P, N> {
    /// Returns `true` if the value is in `[0, p)` (i.e. already a valid [`Fp`]).
    #[inline(always)]
    pub const fn is_canonical(&self) -> bool {
        self.inner.const_lt(&P::MODULUS)
    }

    /// Asserts the value is in `[0, p)` and returns an [`Fp`]. Panics otherwise.
    ///
    /// Use when the value is expected to be canonical. For values that may legitimately be
    /// non-canonical (e.g. cross-field reduction), use [`Fp::reduce_from_bigint`] instead.
    #[inline(always)]
    pub const fn check(self) -> Fp<P, N> {
        assert!(self.is_canonical(), "unverified field element >= modulus");
        Fp { inner: self.inner, _marker: PhantomData }
    }

    /// Asserts the value is in `[0, p)` and returns a reference to the value as [`Fp`]. Panics
    /// otherwise. Zero-cost - no copy, just a pointer cast.
    #[inline(always)]
    pub const fn check_ref(&self) -> &Fp<P, N> {
        assert!(self.is_canonical(), "unverified field element >= modulus");
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
                assert!(other.is_canonical(), "unverified field element >= modulus");
                false
            }
            Ordering::Greater => {
                assert!(self.is_canonical(), "unverified field element >= modulus");
                false
            }
        }
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
        unsafe { &*core::ptr::from_ref(self).cast() }
    }

    /// Computes `-self mod p` in place.
    #[inline]
    pub fn neg_in_place(&mut self) {
        P::Ops::neg_in_place(self);
    }

    /// Computes `self² mod p` in place.
    #[inline]
    pub(crate) fn square_in_place(&mut self) {
        *self = P::Ops::mul(self, self);
    }

    /// Computes `self⁻¹ mod p`. Panics if `self` is zero.
    #[inline]
    pub fn inverse(&self) -> Self {
        P::Ops::inv(self)
    }

    /// Computes `self^exp mod p` via square-and-multiply.
    pub fn pow(&self, exp: &(impl BitAccess + ?Sized)) -> Self {
        let n = exp.bits();
        if n == 0 {
            return Fp::ONE.into();
        }
        let mut acc = *self;
        for i in (0..n - 1).rev() {
            acc.square_in_place();
            if exp.bit(i) {
                acc.mul_assign(self);
            }
        }
        acc
    }

    /// Computes a square root mod p via `self^((p+1)/4)`. Returns `None` if `self` is not a
    /// quadratic residue. Only available when `p % 4 == 3` (enforced at compile time).
    #[inline]
    pub fn sqrt(&self) -> Option<Self> {
        let root = self.pow(&P::MODULUS_PLUS_ONE_DIV_FOUR);
        if (&root * &root).check_is_eq(self) { Some(root) } else { None }
    }
}

impl<P, const N: usize> core::fmt::Debug for UnverifiedFp<P, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("UnverifiedFp").field(self.as_bigint()).finish()
    }
}

impl<P, const N: usize> From<BigInt<N>> for UnverifiedFp<P, N> {
    #[inline]
    fn from(b: BigInt<N>) -> Self {
        Self::from_bigint(b)
    }
}

impl<P, const N: usize> From<Fp<P, N>> for UnverifiedFp<P, N> {
    #[inline]
    fn from(fp: Fp<P, N>) -> Self {
        Self::from_bigint(fp.to_bigint())
    }
}

impl<P, const N: usize> AsRef<Self> for UnverifiedFp<P, N> {
    #[inline]
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<P, const N: usize> AsRef<UnverifiedFp<P, N>> for Fp<P, N> {
    #[inline]
    fn as_ref(&self) -> &UnverifiedFp<P, N> {
        self.as_unverified()
    }
}

// --- Operator impls ---
//
// All arithmetic delegates to the safe P::Ops backend. No unsafe or MaybeUninit needed here.

impl<P: FieldConfig<N>, const N: usize, T: AsRef<UnverifiedFp<P, N>>> Add<&T>
    for &UnverifiedFp<P, N>
{
    type Output = UnverifiedFp<P, N>;
    #[inline]
    fn add(self, rhs: &T) -> UnverifiedFp<P, N> {
        P::Ops::add(self, rhs.as_ref())
    }
}

impl<P: FieldConfig<N>, const N: usize, T: AsRef<UnverifiedFp<P, N>>> Sub<&T>
    for &UnverifiedFp<P, N>
{
    type Output = UnverifiedFp<P, N>;
    #[inline]
    fn sub(self, rhs: &T) -> UnverifiedFp<P, N> {
        P::Ops::sub(self, rhs.as_ref())
    }
}

impl<P: FieldConfig<N>, const N: usize, T: AsRef<UnverifiedFp<P, N>>> Mul<&T>
    for &UnverifiedFp<P, N>
{
    type Output = UnverifiedFp<P, N>;
    #[inline]
    fn mul(self, rhs: &T) -> UnverifiedFp<P, N> {
        P::Ops::mul(self, rhs.as_ref())
    }
}

impl<P: FieldConfig<N>, const N: usize> Neg for &UnverifiedFp<P, N> {
    type Output = UnverifiedFp<P, N>;
    #[inline]
    fn neg(self) -> UnverifiedFp<P, N> {
        P::Ops::neg(self)
    }
}

impl<P: FieldConfig<N>, const N: usize, T: AsRef<Self>> AddAssign<&T> for UnverifiedFp<P, N> {
    #[inline]
    fn add_assign(&mut self, rhs: &T) {
        P::Ops::add_assign(self, rhs.as_ref());
    }
}

impl<P: FieldConfig<N>, const N: usize, T: AsRef<Self>> SubAssign<&T> for UnverifiedFp<P, N> {
    #[inline]
    fn sub_assign(&mut self, rhs: &T) {
        P::Ops::sub_assign(self, rhs.as_ref());
    }
}

impl<P: FieldConfig<N>, const N: usize, T: AsRef<Self>> MulAssign<&T> for UnverifiedFp<P, N> {
    #[inline]
    fn mul_assign(&mut self, rhs: &T) {
        P::Ops::mul_assign(self, rhs.as_ref());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Fp256;

    // Test field: F_7 (arbitrary small prime, independent of any curve).
    enum P {}
    impl FieldConfig<8> for P {
        const MODULUS: BigInt<8> = BigInt::from_u32(7);
        type Ops = crate::field::R0VMFieldOps;
    }

    type F = Fp256<P>;

    fn uf(v: u32) -> UnverifiedFp<P, 8> {
        UnverifiedFp::from_bigint(BigInt::from_u32(v))
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
    fn reduce_from_bigint() {
        assert_eq!(F::reduce_from_bigint(BigInt::from_u32(10)), F::from_u32(3));
        assert_eq!(F::reduce_from_bigint(BigInt::from_u32(3)), F::from_u32(3));
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
