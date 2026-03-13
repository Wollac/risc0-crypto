pub(crate) mod ops;
mod unreduced;

use crate::BigInt;
use bytemuck::TransparentWrapper;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

pub use unreduced::Unreduced;

/// Shorthand for [`Unreduced`] in pointer-heavy signatures.
type Uf<P, const N: usize> = Unreduced<P, N>;

/// Defines a prime field by its modulus. Implement this trait to introduce a new field.
pub trait R0FieldConfig<const N: usize>: Send + Sync + 'static + Sized {
    /// The field modulus `p`.
    const MODULUS: BigInt<N>;

    /// Multiplicative identity.
    const ONE: Fp<Self, N> = Fp::from_bigint_unchecked(BigInt::ONE);
}

/// A prime field with arithmetic operations. Provided by a blanket impl over [`R0FieldConfig`].
///
/// # Safety
///
/// The `fp_*` methods have the following contract:
/// * `out` must point to writeable, aligned memory for `Unreduced<Self, N>`.
/// * `out` need not be initialized - the implementation writes all limbs.
/// * `out` may alias `a` - the implementation reads all inputs before writing.
/// * Results need not be reduced to `[0, p)`.
pub trait FpConfig<const N: usize>: Send + Sync + 'static + Sized {
    /// The field modulus `p`.
    const MODULUS: BigInt<N>;

    /// Additive identity of the field.
    const ZERO: Fp<Self, N> = Fp::from_bigint_unchecked(BigInt::ZERO);

    /// Multiplicative identity of the field.
    const ONE: Fp<Self, N>;

    /// Computes `a + b mod p`.
    /// # Safety
    /// See [trait-level docs](Self).
    unsafe fn fp_add(a: *const Uf<Self, N>, b: &Uf<Self, N>, out: *mut Uf<Self, N>);
    /// Computes `a - b mod p`.
    /// # Safety
    /// See [trait-level docs](Self).
    unsafe fn fp_sub(a: *const Uf<Self, N>, b: &Uf<Self, N>, out: *mut Uf<Self, N>);
    /// Computes `a * b mod p`.
    /// # Safety
    /// See [trait-level docs](Self).
    unsafe fn fp_mul(a: *const Uf<Self, N>, b: &Uf<Self, N>, out: *mut Uf<Self, N>);
    /// Computes `-a mod p`.
    /// # Safety
    /// See [trait-level docs](Self).
    unsafe fn fp_neg(a: &Uf<Self, N>, out: *mut Uf<Self, N>);
    /// Computes `a⁻¹ mod p`. Computing the inverse of zero is undefined behavior.
    /// # Safety
    /// See [trait-level docs](Self).
    unsafe fn fp_inv(a: &Uf<Self, N>, out: *mut Uf<Self, N>);
}

/// An element of the prime field defined by [`P::MODULUS`](FpConfig::MODULUS).
///
/// Operator overloads (`+`, `-`, `*`, unary `-`) produce canonical results in `[0, p)`.
/// For performance-sensitive chains of arithmetic, use [`Unreduced`] which defers the canonicality
/// check until you call [`check`](Unreduced::check).
#[derive(educe::Educe)]
#[educe(Copy, Clone, PartialEq, Eq, Hash)]
#[must_use]
#[repr(transparent)]
pub struct Fp<P, const N: usize> {
    inner: BigInt<N>,
    _marker: core::marker::PhantomData<P>,
}

impl<P, const N: usize> core::fmt::Debug for Fp<P, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Fp").field(self.as_bigint()).finish()
    }
}

pub type Fp256<P> = Fp<P, 8>;
pub type Fp384<P> = Fp<P, 12>;

// ---------------------------------------------------------------------------
// Pure accessors - no arithmetic, no bounds.
// ---------------------------------------------------------------------------

impl<P, const N: usize> Fp<P, N> {
    /// Creates a field element from a [`BigInt`] without checking `< p`.
    #[inline]
    pub const fn from_bigint_unchecked(b: BigInt<N>) -> Self {
        Self { inner: b, _marker: core::marker::PhantomData }
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

    /// Returns a reference to the underlying limb array.
    #[inline]
    pub const fn as_limbs(&self) -> &[u32; N] {
        &self.inner.0
    }

    /// Returns the underlying limb array by value.
    #[inline]
    pub const fn to_limbs(self) -> [u32; N] {
        self.inner.0
    }

    /// Reinterprets this field element as an [`Unreduced`] (zero-cost).
    #[inline]
    pub fn as_unreduced(&self) -> &Unreduced<P, N> {
        Unreduced::wrap_ref(&self.inner)
    }

    /// Reinterprets this field element as `&mut Unreduced` (zero-cost).
    ///
    /// # Safety
    ///
    /// The caller must restore the `< p` invariant before using `self` as `Fp` again
    /// (e.g. via `assert!(self.is_valid())`).
    #[inline]
    unsafe fn as_unreduced_mut(&mut self) -> &mut Unreduced<P, N> {
        Unreduced::wrap_mut(&mut self.inner)
    }
}

// ---------------------------------------------------------------------------
// Arithmetic - requires `P: FpConfig<N>`.
// ---------------------------------------------------------------------------

impl<P: FpConfig<N>, const N: usize> Fp<P, N> {
    /// Additive identity (`0`).
    pub const ZERO: Self = P::ZERO;
    /// Multiplicative identity (`1`).
    pub const ONE: Self = P::ONE;
    /// The field modulus (`p`).
    pub const MODULUS: BigInt<N> = P::MODULUS;

    /// Shift factor for processing byte slices in chunks of `N * 4 - 1` bytes.
    const CHUNK_BASE: Self = {
        let mut limbs = [0u32; N];
        limbs[N - 1] = 1 << (u32::BITS - 8);
        Self::from_bigint_unchecked(BigInt::new(limbs))
    };

    /// Returns `true` if all limbs are zero.
    #[inline]
    pub const fn is_zero(&self) -> bool {
        self.inner.const_eq(&Self::ZERO.inner)
    }

    /// Returns `true` if the limbs represent a canonical field element (i.e. `< p`).
    #[inline]
    const fn is_valid(&self) -> bool {
        self.inner.const_lt(&P::MODULUS)
    }

    /// Creates a field element from a [`BigInt`], returning `None` if the value is `>= p`.
    ///
    /// This is a const fn, so when used via the [`fp!`](crate::fp) macro in const context, an
    /// out-of-range value becomes a compile-time error.
    #[inline]
    pub const fn from_bigint(b: BigInt<N>) -> Option<Self> {
        match b.const_lt(&P::MODULUS) {
            true => Some(Self { inner: b, _marker: core::marker::PhantomData }),
            false => None,
        }
    }

    /// Creates a field element from a `u32`. Panics if `val >= p`.
    #[inline]
    pub const fn from_u32(val: u32) -> Self {
        match Self::from_bigint(BigInt::from_u32(val)) {
            Some(fp) => fp,
            None => panic!("from_u32: value exceeds field modulus"),
        }
    }

    /// Computes `self⁻¹ mod p`. Computing the inverse of zero is undefined behavior.
    #[inline]
    pub fn inverse(&self) -> Self {
        self.as_unreduced().inverse().check()
    }

    /// Creates a field element from a big-endian byte slice, reducing modulo `p`.
    ///
    /// When the input fits in `N * 4` bytes and is already `< p`, no arithmetic is performed.
    #[inline]
    pub fn from_be_bytes_mod_order(bytes: &[u8]) -> Self {
        if bytes.len() <= N * 4 {
            return Unreduced::from_bigint(BigInt::from_be_bytes(bytes)).reduce();
        }

        let chunks = bytes.rchunks_exact(N * 4 - 1);
        let first = chunks.remainder();

        let mut result = Unreduced::from_bigint(BigInt::from_be_bytes(first));
        for chunk in chunks.rev() {
            let chunk_val = Unreduced::from_bigint(BigInt::from_be_bytes(chunk));
            result *= &Self::CHUNK_BASE;
            result += &chunk_val;
        }
        result.check()
    }

    /// Creates a field element from a little-endian byte slice, reducing modulo `p`.
    ///
    /// When the input fits in `N * 4` bytes and is already `< p`, no arithmetic is performed.
    #[cfg(target_endian = "little")]
    #[inline]
    pub fn from_le_bytes_mod_order(bytes: &[u8]) -> Self {
        if bytes.len() <= N * 4 {
            return Unreduced::from_bigint(BigInt::from_le_bytes(bytes)).reduce();
        }

        let chunks = bytes.chunks_exact(N * 4 - 1);
        let first = chunks.remainder();

        let mut result = Unreduced::from_bigint(BigInt::from_le_bytes(first));
        for chunk in chunks.rev() {
            let chunk_val = Unreduced::from_bigint(BigInt::from_le_bytes(chunk));
            result *= &Self::CHUNK_BASE;
            result += &chunk_val;
        }
        result.check()
    }
}

// ---------------------------------------------------------------------------
// Primitive operator impls - checked (canonical output).
//
// - &ref Op &ref: delegates to Unreduced, then .check()
// - val OpAssign &ref: in-place via as_unreduced_mut(), then assert
// ---------------------------------------------------------------------------

impl<P: FpConfig<N>, const N: usize> Add for &Fp<P, N> {
    type Output = Fp<P, N>;
    #[inline]
    fn add(self, rhs: Self) -> Fp<P, N> {
        (self.as_unreduced() + rhs.as_unreduced()).check()
    }
}

impl<P: FpConfig<N>, const N: usize> Sub for &Fp<P, N> {
    type Output = Fp<P, N>;
    #[inline]
    fn sub(self, rhs: Self) -> Fp<P, N> {
        (self.as_unreduced() - rhs.as_unreduced()).check()
    }
}

impl<P: FpConfig<N>, const N: usize> Mul for &Fp<P, N> {
    type Output = Fp<P, N>;
    #[inline]
    fn mul(self, rhs: Self) -> Fp<P, N> {
        (self.as_unreduced() * rhs.as_unreduced()).check()
    }
}

impl<P: FpConfig<N>, const N: usize> Neg for &Fp<P, N> {
    type Output = Fp<P, N>;
    #[inline]
    fn neg(self) -> Fp<P, N> {
        self.as_unreduced().neg().check()
    }
}

impl<P: FpConfig<N>, const N: usize> AddAssign<&Self> for Fp<P, N> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        // SAFETY: is_valid() restores the Fp invariant.
        unsafe { *self.as_unreduced_mut() += rhs.as_unreduced() };
        assert!(self.is_valid());
    }
}

impl<P: FpConfig<N>, const N: usize> SubAssign<&Self> for Fp<P, N> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        // SAFETY: is_valid() restores the Fp invariant.
        unsafe { *self.as_unreduced_mut() -= rhs.as_unreduced() };
        assert!(self.is_valid());
    }
}

impl<P: FpConfig<N>, const N: usize> MulAssign<&Self> for Fp<P, N> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        // SAFETY: is_valid() restores the Fp invariant.
        unsafe { *self.as_unreduced_mut() *= rhs.as_unreduced() };
        assert!(self.is_valid());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test field: F_7 (arbitrary small prime, independent of any curve).
    enum P {}
    impl R0FieldConfig<8> for P {
        const MODULUS: BigInt<8> = BigInt::from_u32(7);
    }

    type F = Fp256<P>;

    #[test]
    fn from_limbs_validation() {
        let v = BigInt::from_u32(4);
        assert!(F::from_bigint(v).is_some());
        assert_eq!(F::from_bigint(v).unwrap().to_bigint(), v);
        assert!(F::from_bigint(F::MODULUS).is_none());
        assert!(F::from_bigint(BigInt::from_u32(8)).is_none());
    }

    #[test]
    fn field_axioms() {
        let (a, b, c) = (F::from_u32(3), F::from_u32(5), F::from_u32(2));

        // commutativity
        assert_eq!(&a + &b, &b + &a);
        assert_eq!(&a * &b, &b * &a);

        // associativity
        assert_eq!(&(&a + &b) + &c, &a + &(&b + &c));
        assert_eq!(&(&a * &b) * &c, &a * &(&b * &c));

        // identity
        assert_eq!(&a + &F::ZERO, a);
        assert_eq!(&a * &F::ONE, a);

        // inverse
        assert_eq!(&a + &(-&a), F::ZERO);
        assert_eq!(&a * &a.inverse(), F::ONE);

        // distributivity
        assert_eq!(&a * &(&b + &c), &(&a * &b) + &(&a * &c));
    }

    #[test]
    fn assign_ops() {
        let (a, b) = (F::from_u32(3), F::from_u32(5));

        let mut r = a;
        r += &b;
        assert_eq!(r, &a + &b);

        let mut r = a;
        r -= &b;
        assert_eq!(r, &a - &b);

        let mut r = a;
        r *= &b;
        assert_eq!(r, &a * &b);
    }

    #[test]
    fn edge_cases() {
        let a = F::from_u32(3);

        assert_eq!(-&F::ZERO, F::ZERO);
        assert_eq!(&a - &a, F::ZERO);
        assert_eq!(&a * &F::ZERO, F::ZERO);
    }

    #[test]
    fn from_be_bytes_mod_order() {
        assert_eq!(F::from_be_bytes_mod_order(&[]), F::ZERO);
        assert_eq!(F::from_be_bytes_mod_order(&[3]), F::from_u32(3));
        assert_eq!(F::from_be_bytes_mod_order(&[7]), F::ZERO);
        assert_eq!(F::from_be_bytes_mod_order(&[10]), F::from_u32(3));
        assert_eq!(F::from_be_bytes_mod_order(&[0xff; 64]), F::from_u32(3));
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn from_le_bytes_mod_order() {
        assert_eq!(F::from_le_bytes_mod_order(&[]), F::ZERO);
        assert_eq!(F::from_le_bytes_mod_order(&[3]), F::from_u32(3));
        assert_eq!(F::from_le_bytes_mod_order(&[7]), F::ZERO);
        assert_eq!(F::from_le_bytes_mod_order(&[10]), F::from_u32(3));
        assert_eq!(F::from_le_bytes_mod_order(&[0xff; 64]), F::from_u32(3));

        // LE vs BE: [0x01, 0x02] means 0x0201 in LE, 0x0102 in BE
        assert_eq!(
            F::from_le_bytes_mod_order(&[0x01, 0x02]),
            F::from_be_bytes_mod_order(&[0x02, 0x01]),
        );
    }

    #[test]
    fn checked_ops_accept_unreduced_input() {
        // 3 + 1*p = 10 in limbs, which represents 3 mod 7 but is not canonical.
        let three_unreduced = F::from_bigint_unchecked(BigInt::from_u32(10));
        let two = F::from_u32(2);

        assert_eq!(&three_unreduced + &two, F::from_u32(5));
        assert_eq!(&three_unreduced * &two, F::from_u32(6));
        assert_eq!(&three_unreduced - &two, F::from_u32(1));
    }
}
