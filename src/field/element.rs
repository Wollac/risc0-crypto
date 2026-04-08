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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BigInt, Fp256,
        field::{FieldConfig, R0VMFieldOps},
    };

    // Test field: F_7 (same as field/mod.rs and field/unverified.rs tests).
    enum P {}
    impl FieldConfig<8> for P {
        const MODULUS: BigInt<8> = BigInt::from_u32(7);
        type Ops = R0VMFieldOps;
    }

    type F = Fp256<P>;
    type UF = crate::UnverifiedFp<P, 8>;

    fn f(v: u32) -> F {
        F::from_u32(v)
    }
    fn uf(v: u32) -> UF {
        UF::from_bigint(BigInt::from_u32(v))
    }

    #[test]
    fn field_trait() {
        assert!(<F as Field>::ZERO.is_zero());
        assert!(!<F as Field>::ONE.is_zero());

        // as_unverified / into_unverified roundtrip
        let a = f(3);
        assert_eq!(Field::as_unverified(&a).check(), a);
        assert_eq!(Field::into_unverified(a).check(), a);

        // neg
        assert_eq!(Field::neg(&f(0)), f(0));
        assert_eq!(Field::neg(&f(3)), f(4)); // -3 mod 7
    }

    #[test]
    fn unverified_field_axioms() {
        let (a, b, c) = (uf(3), uf(5), uf(2));
        let one = Field::into_unverified(F::ONE);

        // commutativity
        assert_eq!(a.add(&b).check(), b.add(&a).check());
        assert_eq!(a.mul(&b).check(), b.mul(&a).check());

        // associativity
        assert_eq!(a.add(&b).add(&c).check(), a.add(&b.add(&c)).check());
        assert_eq!(a.mul(&b).mul(&c).check(), a.mul(&b.mul(&c)).check());

        // identity
        assert_eq!(a.add(&UF::ZERO).check(), f(3));
        assert_eq!(a.mul(&one).check(), f(3));

        // inverse
        let mut neg_a = a;
        neg_a.neg_in_place();
        assert_eq!(a.add(&neg_a).check(), f(0));
        assert_eq!(a.mul(&a.inverse()).check(), f(1));

        // distributivity
        assert_eq!(a.mul(&b.add(&c)).check(), a.mul(&b).add(&a.mul(&c)).check());
    }

    #[test]
    fn unverified_field_assign_ops() {
        let (three, two) = (uf(3), uf(2));

        let mut r = three;
        r.add_assign(&two);
        assert_eq!(r.check(), f(5));
        let mut r = three;
        r.sub_assign(&two);
        assert_eq!(r.check(), f(1));
        let mut r = three;
        r.mul_assign(&two);
        assert_eq!(r.check(), f(6));
        let mut r = three;
        r.neg_in_place();
        assert_eq!(r.check(), f(4)); // -3 mod 7
        let mut r = three;
        r.square_in_place();
        assert_eq!(r.check(), f(2)); // 9 mod 7
    }

    #[test]
    fn unverified_field_check_and_raw() {
        assert_eq!(uf(6).check(), f(6));
        assert_eq!(*uf(3).check_ref(), f(3));
        assert!(uf(3).check_is_eq(&uf(3)));
        assert!(!uf(3).check_is_eq(&uf(5)));

        assert!(uf(3).raw_eq(&uf(3)));
        assert!(!uf(3).raw_eq(&uf(5)));
        assert!(uf(0).raw_is_zero());
        assert!(!uf(1).raw_is_zero());
    }

    #[test]
    fn unverified_field_edge_cases() {
        assert_eq!(uf(3).sub(&uf(3)).check(), f(0));
        assert_eq!(uf(3).mul(&UF::ZERO).check(), f(0));
        let mut z = UF::ZERO;
        z.neg_in_place();
        assert_eq!(z.check(), f(0));
    }

    #[test]
    fn unverified_field_pow() {
        let two = uf(2);
        // 2³ = 8 = 1 mod 7
        assert_eq!(two.pow(&BigInt::<1>::from_u32(3)).check(), f(1));
        // Fermat: a^(p-1) = 1
        assert_eq!(two.pow(&BigInt::<1>::from_u32(6)).check(), f(1));
        // a^0 = 1
        assert_eq!(two.pow(&BigInt::<1>::ZERO).check(), f(1));
    }

    #[test]
    fn unverified_field_non_canonical_input() {
        // 10 in limbs = 3 mod 7, not canonical
        let three = uf(10);
        let two = uf(2);

        assert_eq!(three.add(&two).check(), f(5));
        assert_eq!(three.mul(&two).check(), f(6));
        assert_eq!(three.sub(&two).check(), f(1));
    }

    #[test]
    fn prime_field_trait() {
        assert_eq!(<F as PrimeField<8>>::MODULUS, BigInt::from_u32(7));
        assert_eq!(<F as PrimeField<8>>::MODULUS_BIT_LEN, 3);
        assert_eq!(PrimeField::to_bigint(f(5)), BigInt::from_u32(5));
        assert_eq!(PrimeField::to_bigint(f(0)), BigInt::ZERO);
    }
}
