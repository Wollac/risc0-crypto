pub mod element;
mod ops;
mod unverified;

use crate::{BigInt, BitAccess, LIMBS_256, LIMBS_384};
use bytemuck::TransparentWrapper;
use core::{
    marker::PhantomData,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

pub use element::{Field, PrimeField, UnverifiedField};
pub use ops::R0VMFieldOps;
pub use unverified::UnverifiedFp;

/// Shorthand for [`UnverifiedFp`] in pointer-heavy signatures.
type Uf<P, const N: usize> = UnverifiedFp<P, N>;

/// Field arithmetic operations for a prime field.
///
/// All methods are safe - unsafe FFI is contained within the backend implementation. The four
/// required primitives are `add_assign`, `sub_assign`, `mul_assign`, and `inv`; all other
/// methods have default implementations that delegate to these.
pub trait FieldOps<P: FieldConfig<N>, const N: usize>: Send + Sync + 'static {
    /// Computes `a + b mod p` in place.
    fn add_assign(a: &mut Uf<P, N>, b: &Uf<P, N>);
    /// Computes `a - b mod p` in place.
    fn sub_assign(a: &mut Uf<P, N>, b: &Uf<P, N>);
    /// Computes `a * b mod p` in place.
    fn mul_assign(a: &mut Uf<P, N>, b: &Uf<P, N>);

    /// Computes `a⁻¹ mod p`. Panics if `a` is zero.
    fn inv(a: &Uf<P, N>) -> Uf<P, N>;

    /// Computes `a = 0 - a mod p` in place.
    #[inline]
    fn neg_in_place(a: &mut Uf<P, N>) {
        *a = Self::sub(Uf::wrap_ref(&BigInt::ZERO), a);
    }

    /// Computes `a² mod p` in place.
    #[inline]
    fn square_in_place(a: &mut Uf<P, N>) {
        *a = Self::mul(a, a);
    }

    /// Non-assign version of [`add_assign`](Self::add_assign).
    #[inline]
    fn add(a: &Uf<P, N>, b: &Uf<P, N>) -> Uf<P, N> {
        let mut r = *a;
        Self::add_assign(&mut r, b);
        r
    }

    /// Non-assign version of [`sub_assign`](Self::sub_assign).
    #[inline]
    fn sub(a: &Uf<P, N>, b: &Uf<P, N>) -> Uf<P, N> {
        let mut r = *a;
        Self::sub_assign(&mut r, b);
        r
    }

    /// Non-assign version of [`mul_assign`](Self::mul_assign).
    #[inline]
    fn mul(a: &Uf<P, N>, b: &Uf<P, N>) -> Uf<P, N> {
        let mut r = *a;
        Self::mul_assign(&mut r, b);
        r
    }

    /// Non-assign version of [`neg_in_place`](Self::neg_in_place).
    #[inline]
    fn neg(a: &Uf<P, N>) -> Uf<P, N> {
        let mut r = *a;
        Self::neg_in_place(&mut r);
        r
    }

    /// Reduces `a` into `[0, p)`, returning a canonical [`Fp`].
    #[inline]
    fn reduce(a: &Uf<P, N>) -> Fp<P, N> {
        // a + 0 mod p forces reduction as a side effect
        Self::add(a, Uf::wrap_ref(&BigInt::ZERO)).check()
    }
}

/// Defines a prime field and its arithmetic backend.
///
/// Implement this trait to introduce a new field. The arithmetic is delegated to the associated
/// [`Ops`](Self::Ops) type, which implements [`FieldOps`]. For the R0VM target, use
/// [`R0VMFieldOps`].
pub trait FieldConfig<const N: usize>: Sized + Send + Sync + 'static {
    /// The field modulus `p`.
    const MODULUS: BigInt<N>;

    /// Arithmetic backend for this field.
    type Ops: FieldOps<Self, N>;

    /// Number of bits in the binary representation of the modulus.
    const MODULUS_BIT_LEN: u32 = Self::MODULUS.bit_len();

    /// `floor(p / 2)` - the boundary between the "low" and "high" halves of the field.
    #[doc(hidden)]
    const HALF_MODULUS: BigInt<N> = Self::MODULUS.const_shr(1);

    /// `(p + 1) / 4`, used to compute sqrt when `p % 4 == 3`.
    ///
    /// The default implementation computes this from [`MODULUS`](Self::MODULUS) and asserts
    /// the congruence at compile time. Only evaluated when referenced.
    #[doc(hidden)]
    const MODULUS_PLUS_ONE_DIV_FOUR: BigInt<N> = {
        assert!(Self::MODULUS.0[0] % 4 == 3, "MODULUS_PLUS_ONE_DIV_FOUR requires MODULUS % 4 == 3");
        Self::MODULUS.const_add_u32(1).const_shr(2)
    };

    /// Additive identity of the field.
    const ZERO: Fp<Self, N> = {
        assert!(BigInt::ZERO.const_lt(&Self::MODULUS));
        Fp { inner: BigInt::ZERO, _marker: PhantomData }
    };

    /// Multiplicative identity of the field.
    const ONE: Fp<Self, N> = {
        assert!(BigInt::ONE.const_lt(&Self::MODULUS));
        Fp { inner: BigInt::ONE, _marker: PhantomData }
    };
}

/// An element of the prime field defined by [`P::MODULUS`](FieldConfig::MODULUS).
///
/// # Invariant
///
/// The inner value is always in `[0, p)`. All safe constructors enforce this, and
/// [`from_bigint_unchecked`](Self::from_bigint_unchecked) is `unsafe` because violating it is
/// immediate UB for code that depends on canonicality.
///
/// Operator overloads (`+`, `-`, `*`, unary `-`) produce canonical results in `[0, p)`.
/// For performance-sensitive chains of arithmetic, use [`UnverifiedFp`] which defers the
/// canonicality check. Convert back via [`check`](UnverifiedFp::check) (assert canonical).
#[derive(educe::Educe)]
#[educe(Copy, Clone, PartialEq, Eq, Hash)]
#[must_use]
#[repr(transparent)]
pub struct Fp<P, const N: usize> {
    inner: BigInt<N>,
    _marker: PhantomData<P>,
}

pub type Fp256<P> = Fp<P, LIMBS_256>;
pub type Fp384<P> = Fp<P, LIMBS_384>;

// --- Pure accessors (no arithmetic, no bounds) ---

impl<P, const N: usize> Fp<P, N> {
    /// Creates a field element from a [`BigInt`] without checking `< p`.
    ///
    /// # Safety
    ///
    /// The caller must ensure `b < P::MODULUS`. Violating this breaks the [`Fp`] type invariant.
    #[inline]
    pub const unsafe fn from_bigint_unchecked(b: BigInt<N>) -> Self {
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

    /// Reinterprets this field element as an [`UnverifiedFp`] (zero-cost).
    #[inline]
    pub fn as_unverified(&self) -> &UnverifiedFp<P, N> {
        UnverifiedFp::wrap_ref(&self.inner)
    }

    /// Reinterprets this field element as `&mut UnverifiedFp` (zero-cost).
    ///
    /// # Safety
    ///
    /// The caller must restore the `< p` invariant before using `self` as `Fp` again
    /// (e.g. via `assert!(self.is_valid())`).
    #[inline]
    unsafe fn as_unverified_mut(&mut self) -> &mut UnverifiedFp<P, N> {
        UnverifiedFp::wrap_mut(&mut self.inner)
    }
}

// --- Arithmetic (requires `P: FieldConfig<N>`) ---

impl<P: FieldConfig<N>, const N: usize> Fp<P, N> {
    /// Additive identity (`0`).
    pub const ZERO: Self = P::ZERO;
    /// Multiplicative identity (`1`).
    pub const ONE: Self = P::ONE;
    /// The field modulus (`p`).
    pub const MODULUS: BigInt<N> = P::MODULUS;

    /// Shift factor for processing byte slices in chunks of `N * 4 - 1` bytes.
    const CHUNK_BASE: BigInt<N> = {
        let mut limbs = [0u32; N];
        limbs[N - 1] = 1 << (u32::BITS - 8);
        BigInt::new(limbs)
    };

    /// Creates a field element from a [`BigInt`], returning `None` if the value is `>= p`.
    ///
    /// This is a const fn, so when used via the [`fp!`](crate::fp) macro in const context, an
    /// out-of-range value becomes a compile-time error.
    #[inline]
    pub const fn from_bigint(b: BigInt<N>) -> Option<Self> {
        match b.const_lt(&P::MODULUS) {
            true => Some(Self { inner: b, _marker: PhantomData }),
            false => None,
        }
    }

    /// Creates a field element from a `u32`. Panics if `val >= p`.
    #[inline]
    pub const fn from_u32(val: u32) -> Self {
        if P::MODULUS_BIT_LEN > u32::BITS {
            // modulus > u32::MAX, so any u32 is in range
            Self { inner: BigInt::from_u32(val), _marker: PhantomData }
        } else {
            match Self::from_bigint(BigInt::from_u32(val)) {
                Some(fp) => fp,
                None => panic!("from_u32: value exceeds field modulus"),
            }
        }
    }

    /// Returns `true` if all limbs are zero.
    #[inline]
    pub const fn is_zero(&self) -> bool {
        self.inner.const_eq(&Self::ZERO.inner)
    }

    /// Returns `true` if `self > (p - 1) / 2` (the "high" half of the field).
    #[inline]
    pub const fn is_high(&self) -> bool {
        P::HALF_MODULUS.const_lt(&self.inner)
    }

    /// Computes `self⁻¹ mod p`. Panics if `self` is zero.
    #[inline]
    pub fn inverse(&self) -> Self {
        self.as_unverified().inverse().check()
    }

    /// Computes `self^exp mod p` via square-and-multiply.
    #[inline]
    pub fn pow(&self, exp: &(impl BitAccess + ?Sized)) -> Self {
        self.as_unverified().pow(exp).check()
    }

    /// Computes a square root mod p. Returns `None` if `self` is not a quadratic residue.
    /// Only available when `p % 4 == 3` (enforced at compile time).
    #[inline]
    pub fn sqrt(&self) -> Option<Self> {
        self.as_unverified().sqrt().map(UnverifiedFp::check)
    }

    /// Mathematically reduces an arbitrary [`BigInt`] into a valid field element in `[0, p)`.
    #[inline]
    pub fn reduce_from_bigint(mut b: BigInt<N>) -> Self {
        // fast path: already canonical
        if b < P::MODULUS {
            return unsafe { Self::from_bigint_unchecked(b) };
        }

        // fast path: single subtraction when MSB of modulus is set (2p overflows N limbs,
        // so any value >= p in N limbs is in [p, 2p))
        if P::MODULUS.msb_set() {
            b -= &P::MODULUS;
            return unsafe { Self::from_bigint_unchecked(b) };
        }

        // fallback: delegate to the backend's modular reduction
        P::Ops::reduce(&UnverifiedFp::from_bigint(b))
    }

    /// Creates a field element from a big-endian byte slice, reducing modulo `p`.
    ///
    /// When the input fits in `N * 4` bytes and is already `< p`, no arithmetic is performed.
    #[inline]
    pub fn from_be_bytes_mod_order(bytes: &[u8]) -> Self {
        if bytes.len() <= N * 4 {
            return Self::reduce_from_bigint(BigInt::from_be_bytes(bytes));
        }

        let chunks = bytes.rchunks_exact(N * 4 - 1);
        let first = chunks.remainder();

        let mut result = UnverifiedFp::from_bigint(BigInt::from_be_bytes(first));
        for chunk in chunks.rev() {
            let chunk_val = UnverifiedFp::from_bigint(BigInt::from_be_bytes(chunk));
            result *= UnverifiedFp::wrap_ref(&Self::CHUNK_BASE);
            result += &chunk_val;
        }
        // chunks is non-empty (early return above), so the loop reduces and .check() is sound
        result.check()
    }

    /// Creates a field element from a little-endian byte slice, reducing modulo `p`.
    ///
    /// When the input fits in `N * 4` bytes and is already `< p`, no arithmetic is performed.
    #[cfg(target_endian = "little")]
    #[inline]
    pub fn from_le_bytes_mod_order(bytes: &[u8]) -> Self {
        if bytes.len() <= N * 4 {
            return Self::reduce_from_bigint(BigInt::from_le_bytes(bytes));
        }

        let chunks = bytes.chunks_exact(N * 4 - 1);
        let first = chunks.remainder();

        let mut result = UnverifiedFp::from_bigint(BigInt::from_le_bytes(first));
        for chunk in chunks.rev() {
            let chunk_val = UnverifiedFp::from_bigint(BigInt::from_le_bytes(chunk));
            result *= UnverifiedFp::wrap_ref(&Self::CHUNK_BASE);
            result += &chunk_val;
        }
        // chunks is non-empty (early return above), so the loop reduces and .check() is sound
        result.check()
    }
}

impl<P, const N: usize> From<Fp<P, N>> for BigInt<N> {
    #[inline]
    fn from(fp: Fp<P, N>) -> Self {
        fp.inner
    }
}

impl<P, const N: usize> core::fmt::Debug for Fp<P, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Fp").field(self.as_bigint()).finish()
    }
}

// --- Checked operator impls (canonical output) ---
//
// - &ref Op &ref: delegates to UnverifiedFp, then .check()
// - val OpAssign &ref: in-place via as_unverified_mut(), then assert

impl<P: FieldConfig<N>, const N: usize> Add for &Fp<P, N> {
    type Output = Fp<P, N>;
    #[inline]
    fn add(self, rhs: Self) -> Fp<P, N> {
        (self.as_unverified() + rhs.as_unverified()).check()
    }
}

impl<P: FieldConfig<N>, const N: usize> Sub for &Fp<P, N> {
    type Output = Fp<P, N>;
    #[inline]
    fn sub(self, rhs: Self) -> Fp<P, N> {
        (self.as_unverified() - rhs.as_unverified()).check()
    }
}

impl<P: FieldConfig<N>, const N: usize> Mul for &Fp<P, N> {
    type Output = Fp<P, N>;
    #[inline]
    fn mul(self, rhs: Self) -> Fp<P, N> {
        (self.as_unverified() * rhs.as_unverified()).check()
    }
}

impl<P: FieldConfig<N>, const N: usize> Neg for &Fp<P, N> {
    type Output = Fp<P, N>;
    #[inline]
    fn neg(self) -> Fp<P, N> {
        if self.is_zero() {
            return Fp::ZERO;
        }
        let mut result = P::MODULUS;
        result -= self.as_bigint();
        // SAFETY: self in (0, p) implies p - self in (0, p)
        unsafe { Fp::from_bigint_unchecked(result) }
    }
}

impl<P: FieldConfig<N>, const N: usize, T: AsRef<UnverifiedFp<P, N>>> AddAssign<&T> for Fp<P, N> {
    #[inline]
    fn add_assign(&mut self, rhs: &T) {
        // SAFETY: the assert restores the Fp invariant.
        unsafe { *self.as_unverified_mut() += rhs.as_ref() };
        if self.inner >= P::MODULUS {
            unverified::canonical_panic();
        }
    }
}

impl<P: FieldConfig<N>, const N: usize, T: AsRef<UnverifiedFp<P, N>>> SubAssign<&T> for Fp<P, N> {
    #[inline]
    fn sub_assign(&mut self, rhs: &T) {
        // SAFETY: the assert restores the Fp invariant.
        unsafe { *self.as_unverified_mut() -= rhs.as_ref() };
        if self.inner >= P::MODULUS {
            unverified::canonical_panic();
        }
    }
}

impl<P: FieldConfig<N>, const N: usize, T: AsRef<UnverifiedFp<P, N>>> MulAssign<&T> for Fp<P, N> {
    #[inline]
    fn mul_assign(&mut self, rhs: &T) {
        // SAFETY: the assert restores the Fp invariant.
        unsafe { *self.as_unverified_mut() *= rhs.as_ref() };
        if self.inner >= P::MODULUS {
            unverified::canonical_panic();
        }
    }
}

// --- Field trait impls ---

impl<P: FieldConfig<N>, const N: usize> Field for Fp<P, N> {
    type Unverified = UnverifiedFp<P, N>;

    const ZERO: Self = P::ZERO;
    const ONE: Self = P::ONE;

    #[inline]
    fn is_zero(&self) -> bool {
        self.is_zero()
    }

    #[inline]
    fn as_unverified(&self) -> &UnverifiedFp<P, N> {
        self.as_unverified()
    }

    #[inline]
    fn into_unverified(self) -> UnverifiedFp<P, N> {
        self.into()
    }

    #[inline]
    fn neg(&self) -> Self {
        -self
    }
}

impl<P: FieldConfig<N>, const N: usize> PrimeField<N> for Fp<P, N> {
    const MODULUS: BigInt<N> = P::MODULUS;
    const MODULUS_BIT_LEN: u32 = P::MODULUS_BIT_LEN;

    #[inline]
    fn to_bigint(self) -> BigInt<N> {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test field: F_7 (arbitrary small prime, independent of any curve).
    enum P {}
    impl FieldConfig<8> for P {
        const MODULUS: BigInt<8> = BigInt::from_u32(7);
        type Ops = R0VMFieldOps;
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
        let (three, five) = (F::from_u32(3), F::from_u32(5));

        let mut r = three;
        r += &five;
        assert_eq!(r, &three + &five);
        let mut r = three;
        r -= &five;
        assert_eq!(r, &three - &five);
        let mut r = three;
        r *= &five;
        assert_eq!(r, &three * &five);
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
    fn pow_and_sqrt() {
        let two = F::from_u32(2);
        // pow: 2³ = 8 = 1 mod 7
        assert_eq!(two.pow(&BigInt::<1>::from_u32(3)), F::ONE);
        // Fermat's little theorem: a^(p-1) = 1
        assert_eq!(two.pow(&BigInt::<1>::from_u32(6)), F::ONE);
        // a^0 = 1
        assert_eq!(two.pow(&BigInt::<1>::ZERO), F::ONE);

        // sqrt: quadratic residues in F_7 are {0, 1, 2, 4}
        // sqrt(0) = 0, sqrt(1) = 1 or 6, sqrt(2) = 3 or 4, sqrt(4) = 2 or 5
        assert_eq!(F::ZERO.sqrt(), Some(F::ZERO));
        for a in [1u32, 2, 4] {
            let root = F::from_u32(a).sqrt().unwrap();
            assert_eq!(&root * &root, F::from_u32(a));
        }
        // non-residues: {3, 5, 6}
        for a in [3u32, 5, 6] {
            assert!(F::from_u32(a).sqrt().is_none());
        }
    }
}
