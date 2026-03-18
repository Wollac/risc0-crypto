//! R0VM field arithmetic backend.
//!
//! This module connects [`R0FieldConfig`] to [`FpConfig`] via a blanket impl backed by
//! `risc0_bigint2` unchecked field operations.
//!
//! Swapping to a different backend (e.g. Montgomery-form host, different zkVM) means replacing this
//! module - the rest of the crate is backend-agnostic.

use super::Uf;
use crate::{BigInt, Fp, FpConfig, R0FieldConfig};
use bytemuck::TransparentWrapper;
use risc0_bigint2::field::unchecked::{
    modadd_256, modadd_384, modinv_256, modinv_384, modmul_256, modmul_384, modsub_256, modsub_384,
};

/// Width-specific modular arithmetic over raw pointers.
///
/// Implemented only for [`BigInt<8>`] (256-bit) and [`BigInt<12>`] (384-bit).
///
/// # Safety
///
/// For every method:
/// * `a` and `b` must point to readable, aligned memory for `Self`.
/// * `out` must point to writeable, aligned memory for `Self`.
/// * `out` need not be initialized - the implementation writes all limbs.
/// * `out` may alias `a` or `b` - the FFI reads all inputs before writing.
trait FieldOps {
    unsafe fn add(a: *const Self, b: *const Self, m: &Self, out: *mut Self);
    unsafe fn sub(a: *const Self, b: *const Self, m: &Self, out: *mut Self);
    unsafe fn mul(a: *const Self, b: *const Self, m: &Self, out: *mut Self);
    unsafe fn inv(a: *const Self, m: &Self, out: *mut Self);
}

impl FieldOps for BigInt<8> {
    #[inline]
    unsafe fn add(a: *const Self, b: *const Self, m: &Self, out: *mut Self) {
        unsafe { modadd_256(&(*a).0, &(*b).0, &m.0, &mut (*out).0) }
    }
    #[inline]
    unsafe fn sub(a: *const Self, b: *const Self, m: &Self, out: *mut Self) {
        unsafe { modsub_256(&(*a).0, &(*b).0, &m.0, &mut (*out).0) }
    }
    #[inline]
    unsafe fn mul(a: *const Self, b: *const Self, m: &Self, out: *mut Self) {
        unsafe { modmul_256(&(*a).0, &(*b).0, &m.0, &mut (*out).0) }
    }
    #[inline]
    unsafe fn inv(a: *const Self, m: &Self, out: *mut Self) {
        unsafe { modinv_256(&(*a).0, &m.0, &mut (*out).0) }
    }
}

impl FieldOps for BigInt<12> {
    #[inline]
    unsafe fn add(a: *const Self, b: *const Self, m: &Self, out: *mut Self) {
        unsafe { modadd_384(&(*a).0, &(*b).0, &m.0, &mut (*out).0) }
    }
    #[inline]
    unsafe fn sub(a: *const Self, b: *const Self, m: &Self, out: *mut Self) {
        unsafe { modsub_384(&(*a).0, &(*b).0, &m.0, &mut (*out).0) }
    }
    #[inline]
    unsafe fn mul(a: *const Self, b: *const Self, m: &Self, out: *mut Self) {
        unsafe { modmul_384(&(*a).0, &(*b).0, &m.0, &mut (*out).0) }
    }
    #[inline]
    unsafe fn inv(a: *const Self, m: &Self, out: *mut Self) {
        unsafe { modinv_384(&(*a).0, &m.0, &mut (*out).0) }
    }
}

// --- Blanket: FieldConfig + FieldOps -> PrimeFieldConfig ---
//
// This is the only place in the crate that knows about the R0VM backend.
// Replacing this blanket impl (and the FieldOps impls above) is all that's
// needed to retarget to a different backend.

/// Mutable pointer cast guarded by [`TransparentWrapper`].
const fn cast_ptr_mut<T: TransparentWrapper<Inner>, Inner>(ptr: *mut T) -> *mut Inner {
    ptr.cast()
}

/// Const pointer cast guarded by [`TransparentWrapper`].
const fn cast_ptr<T: TransparentWrapper<Inner>, Inner>(ptr: *const T) -> *const Inner {
    ptr.cast()
}

impl<P: R0FieldConfig<N>, const N: usize> FpConfig<N> for P
where
    BigInt<N>: FieldOps,
{
    const MODULUS: BigInt<N> = <Self as R0FieldConfig<N>>::MODULUS;
    const ONE: Fp<Self, N> = <Self as R0FieldConfig<N>>::ONE;

    #[inline]
    unsafe fn fp_add(a: *const Uf<Self, N>, b: *const Uf<Self, N>, out: *mut Uf<Self, N>) {
        unsafe { FieldOps::add(cast_ptr(a), cast_ptr(b), &Self::MODULUS, cast_ptr_mut(out)) }
    }

    #[inline]
    unsafe fn fp_sub(a: *const Uf<Self, N>, b: *const Uf<Self, N>, out: *mut Uf<Self, N>) {
        unsafe { FieldOps::sub(cast_ptr(a), cast_ptr(b), &Self::MODULUS, cast_ptr_mut(out)) }
    }

    #[inline]
    unsafe fn fp_mul(a: *const Uf<Self, N>, b: *const Uf<Self, N>, out: *mut Uf<Self, N>) {
        unsafe { FieldOps::mul(cast_ptr(a), cast_ptr(b), &Self::MODULUS, cast_ptr_mut(out)) }
    }

    #[inline]
    unsafe fn fp_neg(a: *const Uf<Self, N>, out: *mut Uf<Self, N>) {
        unsafe { FieldOps::sub(&BigInt::ZERO, cast_ptr(a), &Self::MODULUS, cast_ptr_mut(out)) }
    }

    #[inline]
    unsafe fn fp_inv(a: &Uf<Self, N>, out: *mut Uf<Self, N>) {
        unsafe { FieldOps::inv(a.as_bigint(), &Self::MODULUS, cast_ptr_mut(out)) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    const A: BigInt<8> = BigInt::from_u32(3);
    const B: BigInt<8> = BigInt::from_u32(5);
    const M: BigInt<8> = BigInt::from_u32(7);

    #[test]
    fn add_aliasing() {
        let mut a = A;
        unsafe { FieldOps::add(ptr::from_ref(&a), &B, &M, ptr::from_mut(&mut a)) };
        assert_eq!(a, BigInt::from_u32(1)); // (3 + 5) mod 7

        let mut b = B;
        unsafe { FieldOps::add(&A, ptr::from_ref(&b), &M, ptr::from_mut(&mut b)) };
        assert_eq!(b, BigInt::from_u32(1));
    }

    #[test]
    fn sub_aliasing() {
        let mut a = A;
        unsafe { FieldOps::sub(ptr::from_ref(&a), &B, &M, ptr::from_mut(&mut a)) };
        assert_eq!(a, BigInt::from_u32(5)); // (3 - 5) mod 7

        let mut b = B;
        unsafe { FieldOps::sub(&A, ptr::from_ref(&b), &M, ptr::from_mut(&mut b)) };
        assert_eq!(b, BigInt::from_u32(5));
    }

    #[test]
    fn mul_aliasing() {
        let mut a = A;
        unsafe { FieldOps::mul(ptr::from_ref(&a), &B, &M, ptr::from_mut(&mut a)) };
        assert_eq!(a, BigInt::from_u32(1)); // (3 * 5) mod 7

        let mut b = B;
        unsafe { FieldOps::mul(&A, ptr::from_ref(&b), &M, ptr::from_mut(&mut b)) };
        assert_eq!(b, BigInt::from_u32(1));
    }

    #[test]
    fn neg_aliasing() {
        let mut a = A;
        unsafe { FieldOps::sub(&BigInt::ZERO, ptr::from_ref(&a), &M, ptr::from_mut(&mut a)) };
        assert_eq!(a, BigInt::from_u32(4)); // -3 mod 7
    }

    #[test]
    fn inv_aliasing() {
        let mut a = A;
        unsafe { FieldOps::inv(ptr::from_ref(&a), &M, ptr::from_mut(&mut a)) };
        assert_eq!(a, BigInt::from_u32(5)); // 3⁻¹ mod 7 = 5
    }
}
