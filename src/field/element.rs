//! Abstract field element traits for generic curve arithmetic.
//!
//! [`Field`] and [`UnverifiedField`] abstract over concrete field types (`Fp`, `Fp2`, etc.),
//! allowing [`AffinePoint`](crate::AffinePoint) to work generically over any base field.
//! [`PrimeField`] extends `Field` with BigInt access needed by circuit-blob-accelerated EC ops.

use crate::{BigInt, BitAccess};
use bytemuck::TransparentWrapper;
use core::{fmt::Debug, hash::Hash};

/// A verified (canonical) field element.
///
/// Both [`Fp`](crate::Fp) and future extension field types implement this trait, enabling
/// [`CurveConfig`](crate::CurveConfig) to be generic over the base field.
pub trait Field: Copy + Clone + PartialEq + Eq + Hash + Debug + Send + Sync + 'static {
    /// The unverified counterpart for deferred-check arithmetic.
    type Unverified: UnverifiedField<Verified = Self>;

    /// Additive identity.
    const ZERO: Self;
    /// Multiplicative identity.
    const ONE: Self;

    /// Returns `true` if this element is zero.
    fn is_zero(&self) -> bool;

    /// Zero-cost reinterpret as the unverified type.
    fn as_unverified(&self) -> &Self::Unverified;

    /// Converts to the unverified type by value.
    fn into_unverified(self) -> Self::Unverified;

    /// Computes `-self`.
    fn neg(&self) -> Self;
}

/// An unverified field element for deferred-check arithmetic.
///
/// Arithmetic is always sound (correct mod p), but the result may not be canonical (`< p`).
/// Call [`check`](Self::check) to assert canonicality and obtain a [`Field`] element.
pub trait UnverifiedField: Copy + Clone + Debug + Send + Sync + 'static {
    /// The verified counterpart.
    type Verified: Field<Unverified = Self>;

    /// Additive identity (canonical zero).
    const ZERO: Self;

    // --- arithmetic ---

    /// `a + b mod p`
    fn add(&self, other: &Self) -> Self;
    /// `a - b mod p`
    fn sub(&self, other: &Self) -> Self;
    /// `a * b mod p`
    fn mul(&self, other: &Self) -> Self;
    /// `a + b mod p` in place
    fn add_assign(&mut self, other: &Self);
    /// `a - b mod p` in place
    fn sub_assign(&mut self, other: &Self);
    /// `a * b mod p` in place
    fn mul_assign(&mut self, other: &Self);
    /// `-a mod p` in place
    fn neg_in_place(&mut self);
    /// `a² mod p` in place
    fn square_in_place(&mut self);
    /// `a⁻¹ mod p`. Panics if zero.
    fn inverse(&self) -> Self;

    /// `self^exp mod p` via square-and-multiply.
    fn pow(&self, exp: &(impl BitAccess + ?Sized)) -> Self {
        let n = exp.bits();
        if n == 0 {
            return Self::Verified::ONE.into_unverified();
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

    // --- verification boundary ---

    /// Asserts `< p` and returns the canonical element. Panics otherwise.
    fn check(self) -> Self::Verified;
    /// Asserts `< p` and returns a reference. Zero-cost. Panics otherwise.
    fn check_ref(&self) -> &Self::Verified;
    /// Field equality using check semantics. Returns `true` if equal; asserts the larger value
    /// is canonical when they differ.
    fn check_is_eq(&self, other: &Self) -> bool;
    /// Raw integer equality (may give false negatives for non-canonical values).
    fn raw_eq(&self, other: &Self) -> bool;
    /// Raw integer zero check (not field equality - only catches canonical zero).
    fn raw_is_zero(&self) -> bool;
}

/// A prime field element with BigInt access.
///
/// Extends [`Field`] with the modulus, `to_bigint()`, and a `TransparentWrapper` bound on the
/// unverified type. This provides everything needed for:
/// - Circuit-blob-accelerated EC operations ([`R0VMCurveOps`](crate::R0VMCurveOps))
/// - ECDSA cross-field conversions
/// - Point decompression (`ys_from_x`)
pub trait PrimeField<const N: usize>: Field<Unverified: TransparentWrapper<BigInt<N>>> {
    /// The field modulus `p`.
    const MODULUS: BigInt<N>;
    /// Number of bits in the modulus.
    const MODULUS_BIT_LEN: u32;
    /// Returns the underlying [`BigInt`] by value.
    fn to_bigint(self) -> BigInt<N>;
}
