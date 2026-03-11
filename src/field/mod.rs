pub(crate) mod ops;
mod unreduced;

pub use unreduced::Unreduced;

use crate::BigInt;
use core::{
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    ptr,
};

pub trait R0FieldConfig<const N: usize>: Send + Sync + 'static + Sized {
    /// The field modulus `p`.
    const MODULUS: BigInt<N>;

    /// Multiplicative identity.
    const ONE: Fp<Self, N> = Fp::from_bigint_unchecked(BigInt::ONE);
}

/// A fully configured prime field with hardware-accelerated arithmetic.
///
/// # Safety (for the blanket impl)
///
/// The `fp_*` methods have the following contract:
/// * `out` must point to writeable, aligned memory for `Fp<Self, N>`.
/// * `out` need not be initialized — the implementation writes all limbs.
/// * `out` may alias `a` or `b` — the implementation reads all inputs before writing.
pub trait FpConfig<const N: usize>: Send + Sync + 'static + Sized {
    /// The field modulus `p`.
    const MODULUS: BigInt<N>;

    /// Additive identity of the field.
    const ZERO: Fp<Self, N> = Fp::from_bigint_unchecked(BigInt::ZERO);

    /// Multiplicative identity of the field.
    const ONE: Fp<Self, N>;

    #[doc(hidden)]
    unsafe fn fp_add(a: &Fp<Self, N>, b: &Fp<Self, N>, out: *mut Fp<Self, N>);
    #[doc(hidden)]
    unsafe fn fp_sub(a: &Fp<Self, N>, b: &Fp<Self, N>, out: *mut Fp<Self, N>);
    #[doc(hidden)]
    unsafe fn fp_mul(a: &Fp<Self, N>, b: &Fp<Self, N>, out: *mut Fp<Self, N>);
    #[doc(hidden)]
    unsafe fn fp_inv(a: &Fp<Self, N>, out: *mut Fp<Self, N>);
}

/// An element of the prime field defined by [`P::MODULUS`](FpConfig::MODULUS).
///
/// Operator overloads (`+`, `-`, `*`, unary `-`) produce canonical results in `[0, p)`.
/// For performance-sensitive chains of arithmetic, use [`Unreduced`] which defers
/// the canonicality check until you call [`.check()`](Unreduced::check).
#[repr(transparent)]
#[derive(educe::Educe)]
#[educe(Copy, Clone, PartialEq, Eq, Hash)]
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
// Pure accessors — no arithmetic, no bounds.
// ---------------------------------------------------------------------------

impl<P, const N: usize> Fp<P, N> {
    /// Creates a field element from a [`BigInt`] without checking `< p`.
    #[inline]
    pub const fn from_bigint_unchecked(b: BigInt<N>) -> Self {
        Self { inner: b, _marker: core::marker::PhantomData }
    }

    #[inline]
    pub const fn as_bigint(&self) -> &BigInt<N> {
        &self.inner
    }

    #[inline]
    pub const fn to_bigint(self) -> BigInt<N> {
        self.inner
    }

    /// Returns a reference to the underlying limb array.
    #[inline]
    pub const fn as_limbs(&self) -> &[u32; N] {
        &self.inner.0
    }

    #[inline]
    pub const fn to_limbs(self) -> [u32; N] {
        self.inner.0
    }

    /// Reinterprets this field element as an [`Unreduced`] (zero-cost).
    #[inline]
    pub const fn as_unreduced(&self) -> &Unreduced<P, N> {
        unsafe { &*ptr::from_ref(self).cast() }
    }

    /// Transparent pointer cast from `&Fp<P, N>` to `*const BigInt<N>`.
    ///
    /// Sound because `Fp` is `#[repr(transparent)]` over `BigInt<N>`.
    /// Used by [`FpOps`] default methods to bridge into [`FieldOps`](ops::FieldOps).
    #[inline]
    const fn as_raw(&self) -> *const BigInt<N> {
        ptr::from_ref(self).cast()
    }
}

// ---------------------------------------------------------------------------
// Arithmetic — requires `P: PrimeFieldConfig<N>`.
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
        let fp = Self::from_bigint_unchecked(b);
        match fp.is_valid() {
            true => Some(fp),
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

    #[inline(always)]
    pub fn reduce_in_place(&mut self) {
        if self.is_valid() {
            return;
        }
        // If MSB of modulus is set, 2p overflows N limbs, so a >= p implies a ∈ [p, 2p).
        if P::MODULUS.msb_set() {
            self.inner -= &P::MODULUS;
            return;
        }
        // Adding zero forces reduction
        *self += &Self::ZERO
    }

    /// Returns `self` reduced to its canonical representative in `[0, p)`.
    #[must_use]
    #[inline]
    pub fn reduced(mut self) -> Self {
        self.reduce_in_place();
        self
    }

    /// Computes `self⁻¹ mod p`. Panics in debug builds if `self` is zero.
    #[must_use]
    #[inline]
    pub fn inverse(&self) -> Self {
        self.as_unreduced().inverse().check()
    }

    /// Creates a field element from a big-endian byte slice, reducing modulo `p`.
    ///
    /// When the input fits in `N * 4` bytes and is already `< p`, no syscalls are issued.
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
    /// When the input fits in `N * 4` bytes and is already `< p`, no syscalls are issued.
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

    // -----------------------------------------------------------------------
    // Crate-internal unchecked entry points for Unreduced.
    // -----------------------------------------------------------------------

    #[inline]
    unsafe fn add_into(a: &Self, b: &Self, out: *mut Self) {
        unsafe { P::fp_add(a, b, out) }
    }
    #[inline]
    unsafe fn sub_into(a: &Self, b: &Self, out: *mut Self) {
        unsafe { P::fp_sub(a, b, out) }
    }
    #[inline]
    unsafe fn mul_into(a: &Self, b: &Self, out: *mut Self) {
        unsafe { P::fp_mul(a, b, out) }
    }
    #[inline]
    unsafe fn neg_into(a: &Self, out: *mut Self) {
        unsafe { P::fp_sub(&Self::ZERO, a, out) }
    }
    #[inline]
    unsafe fn inv_into(a: &Self, out: *mut Self) {
        unsafe { P::fp_inv(a, out) }
    }
}

// ---------------------------------------------------------------------------
// Operator overloads — checked (canonical output).
//
// All reference-based to avoid 32-byte / 48-byte copies on R0VM
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

// ---------------------------------------------------------------------------
// Assign operators — checked, in-place (aliased input/output, zero copies).
// ---------------------------------------------------------------------------

impl<P: FpConfig<N>, const N: usize> AddAssign<&Self> for Fp<P, N> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        let ptr = ptr::from_mut(self);
        unsafe { P::fp_add(&*ptr, rhs, ptr) };
        assert!(self.is_valid());
    }
}

impl<P: FpConfig<N>, const N: usize> SubAssign<&Self> for Fp<P, N> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        let ptr = ptr::from_mut(self);
        unsafe { P::fp_sub(&*ptr, rhs, ptr) };
        assert!(self.is_valid());
    }
}

impl<P: FpConfig<N>, const N: usize> MulAssign<&Self> for Fp<P, N> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        let ptr = ptr::from_mut(self);
        unsafe { P::fp_mul(&*ptr, rhs, ptr) };
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

        // Commutativity
        assert_eq!(&a + &b, &b + &a);
        assert_eq!(&a * &b, &b * &a);

        // Associativity
        assert_eq!(&(&a + &b) + &c, &a + &(&b + &c));
        assert_eq!(&(&a * &b) * &c, &a * &(&b * &c));

        // Identity
        assert_eq!(&a + &F::ZERO, a);
        assert_eq!(&a * &F::ONE, a);

        // Inverse
        assert_eq!(&a + &(-&a), F::ZERO);
        assert_eq!(&a * &a.inverse(), F::ONE);

        // Distributivity
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
