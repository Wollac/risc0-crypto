//! R0VM field arithmetic backend.
//!
//! This module provides [`R0VMFieldOps`], the R0VM [`FieldOps`] implementation backed by
//! `risc0_bigint2` unchecked field operations.
//!
//! Swapping to a different backend (e.g. Montgomery-form host, different zkVM) means replacing
//! this module - the rest of the crate is backend-agnostic.

use super::Uf;
use crate::{
    BigInt,
    field::{FieldConfig, FieldOps},
};
use bytemuck::TransparentWrapper;
use core::{mem::MaybeUninit, ptr};
use risc0_bigint2::field::unchecked::{
    modadd_256, modadd_384, modinv_256, modinv_384, modmul_256, modmul_384, modsub_256, modsub_384,
};

/// Width-specific FFI dispatch for `risc0_bigint2` modular arithmetic.
///
/// Implemented only for [`BigInt<8>`] (256-bit) and [`BigInt<12>`] (384-bit).
///
/// # Safety
///
/// For `sys_add`, `sys_sub`, `sys_mul`:
/// - All pointer arguments must be readable and aligned.
/// - `out` must point to writable, aligned memory (need not be initialized).
/// - `out` may alias `a` or `b` - the FFI reads all inputs before writing.
///
/// For `sys_inv`:
/// - `out` must point to writable, aligned memory (need not be initialized).
/// - `out` must NOT alias `a`.
trait FieldFfi {
    unsafe fn sys_add(a: *const Self, b: *const Self, m: &Self, out: *mut Self);
    unsafe fn sys_sub(a: *const Self, b: *const Self, m: &Self, out: *mut Self);
    unsafe fn sys_mul(a: *const Self, b: *const Self, m: &Self, out: *mut Self);
    unsafe fn sys_inv(a: &Self, m: &Self, out: *mut Self);
}

impl FieldFfi for BigInt<8> {
    #[inline(always)]
    unsafe fn sys_add(a: *const Self, b: *const Self, m: &Self, out: *mut Self) {
        unsafe { modadd_256(&(*a).0, &(*b).0, &m.0, &mut (*out).0) }
    }
    #[inline(always)]
    unsafe fn sys_sub(a: *const Self, b: *const Self, m: &Self, out: *mut Self) {
        unsafe { modsub_256(&(*a).0, &(*b).0, &m.0, &mut (*out).0) }
    }
    #[inline(always)]
    unsafe fn sys_mul(a: *const Self, b: *const Self, m: &Self, out: *mut Self) {
        unsafe { modmul_256(&(*a).0, &(*b).0, &m.0, &mut (*out).0) }
    }
    #[inline(always)]
    unsafe fn sys_inv(a: &Self, m: &Self, out: *mut Self) {
        unsafe { modinv_256(&a.0, &m.0, &mut (*out).0) }
    }
}

impl FieldFfi for BigInt<12> {
    #[inline(always)]
    unsafe fn sys_add(a: *const Self, b: *const Self, m: &Self, out: *mut Self) {
        unsafe { modadd_384(&(*a).0, &(*b).0, &m.0, &mut (*out).0) }
    }
    #[inline(always)]
    unsafe fn sys_sub(a: *const Self, b: *const Self, m: &Self, out: *mut Self) {
        unsafe { modsub_384(&(*a).0, &(*b).0, &m.0, &mut (*out).0) }
    }
    #[inline(always)]
    unsafe fn sys_mul(a: *const Self, b: *const Self, m: &Self, out: *mut Self) {
        unsafe { modmul_384(&(*a).0, &(*b).0, &m.0, &mut (*out).0) }
    }
    #[inline(always)]
    unsafe fn sys_inv(a: &Self, m: &Self, out: *mut Self) {
        unsafe { modinv_384(&a.0, &m.0, &mut (*out).0) }
    }
}

/// Mutable pointer cast guarded by [`TransparentWrapper`].
const fn cast_ptr_mut<T: TransparentWrapper<Inner>, Inner>(ptr: *mut T) -> *mut Inner {
    ptr.cast()
}

/// Const pointer cast guarded by [`TransparentWrapper`].
const fn cast_ptr<T: TransparentWrapper<Inner>, Inner>(ptr: *const T) -> *const Inner {
    ptr.cast()
}

/// R0VM backend for field arithmetic, backed by `risc0_bigint2` unchecked field operations.
pub enum R0VMFieldOps {}

impl<P: FieldConfig<N>, const N: usize> FieldOps<P, N> for R0VMFieldOps
where
    BigInt<N>: FieldFfi,
{
    #[inline]
    fn add_assign(a: &mut Uf<P, N>, b: &Uf<P, N>) {
        let ptr = cast_ptr_mut(ptr::from_mut(a));
        // SAFETY: out aliases a per FieldFfi contract.
        unsafe { FieldFfi::sys_add(ptr, cast_ptr(b), &P::MODULUS, ptr) }
    }

    #[inline]
    fn sub_assign(a: &mut Uf<P, N>, b: &Uf<P, N>) {
        let ptr = cast_ptr_mut(ptr::from_mut(a));
        // SAFETY: out aliases a per FieldFfi contract.
        unsafe { FieldFfi::sys_sub(ptr, cast_ptr(b), &P::MODULUS, ptr) }
    }

    #[inline]
    fn mul_assign(a: &mut Uf<P, N>, b: &Uf<P, N>) {
        let ptr = cast_ptr_mut(ptr::from_mut(a));
        // SAFETY: out aliases a per FieldFfi contract.
        unsafe { FieldFfi::sys_mul(ptr, cast_ptr(b), &P::MODULUS, ptr) }
    }

    #[inline]
    fn inv(a: &Uf<P, N>) -> Uf<P, N> {
        // SAFETY: out is fully written by sys_inv before assume_init.
        unsafe {
            let mut out = MaybeUninit::uninit();
            FieldFfi::sys_inv(a.as_bigint(), &P::MODULUS, cast_ptr_mut(out.as_mut_ptr()));
            out.assume_init()
        }
    }

    #[inline]
    fn neg_in_place(a: &mut Uf<P, N>) {
        let ptr = cast_ptr_mut(ptr::from_mut(a));
        // SAFETY: out aliases a per FieldFfi contract.
        unsafe { FieldFfi::sys_sub(&BigInt::ZERO, ptr, &P::MODULUS, ptr) }
    }

    #[inline]
    fn square_in_place(a: &mut Uf<P, N>) {
        let ptr = cast_ptr_mut(ptr::from_mut(a));
        // SAFETY: out aliases a per FieldFfi contract; sys_mul reads all inputs before writing.
        unsafe { FieldFfi::sys_mul(ptr, ptr, &P::MODULUS, ptr) }
    }

    #[inline]
    fn add(a: &Uf<P, N>, b: &Uf<P, N>) -> Uf<P, N> {
        // SAFETY: out is fully written by sys_add before assume_init.
        unsafe {
            let mut out = MaybeUninit::uninit();
            FieldFfi::sys_add(
                cast_ptr(a),
                cast_ptr(b),
                &P::MODULUS,
                cast_ptr_mut(out.as_mut_ptr()),
            );
            out.assume_init()
        }
    }

    #[inline]
    fn sub(a: &Uf<P, N>, b: &Uf<P, N>) -> Uf<P, N> {
        // SAFETY: out is fully written by sys_sub before assume_init.
        unsafe {
            let mut out = MaybeUninit::uninit();
            FieldFfi::sys_sub(
                cast_ptr(a),
                cast_ptr(b),
                &P::MODULUS,
                cast_ptr_mut(out.as_mut_ptr()),
            );
            out.assume_init()
        }
    }

    #[inline]
    fn mul(a: &Uf<P, N>, b: &Uf<P, N>) -> Uf<P, N> {
        // SAFETY: out is fully written by sys_mul before assume_init.
        unsafe {
            let mut out = MaybeUninit::uninit();
            FieldFfi::sys_mul(
                cast_ptr(a),
                cast_ptr(b),
                &P::MODULUS,
                cast_ptr_mut(out.as_mut_ptr()),
            );
            out.assume_init()
        }
    }

    #[inline]
    fn neg(a: &Uf<P, N>) -> Uf<P, N> {
        // SAFETY: out is fully written by sys_sub before assume_init.
        unsafe {
            let mut out = MaybeUninit::uninit();
            FieldFfi::sys_sub(
                &BigInt::ZERO,
                cast_ptr(a),
                &P::MODULUS,
                cast_ptr_mut(out.as_mut_ptr()),
            );
            out.assume_init()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::from_mut;

    const A: BigInt<8> = BigInt::from_u32(3);
    const B: BigInt<8> = BigInt::from_u32(5);
    const M: BigInt<8> = BigInt::from_u32(7);

    #[test]
    fn add_aliasing() {
        let mut a = A;
        let ptr = from_mut(&mut a);
        unsafe { FieldFfi::sys_add(ptr, &B, &M, ptr) };
        assert_eq!(a, BigInt::from_u32(1)); // (3 + 5) mod 7

        let mut b = B;
        let ptr = from_mut(&mut b);
        unsafe { FieldFfi::sys_add(&A, ptr, &M, ptr) };
        assert_eq!(b, BigInt::from_u32(1));
    }

    #[test]
    fn sub_aliasing() {
        let mut a = A;
        let ptr = from_mut(&mut a);
        unsafe { FieldFfi::sys_sub(ptr, &B, &M, ptr) };
        assert_eq!(a, BigInt::from_u32(5)); // (3 - 5) mod 7

        let mut b = B;
        let ptr = from_mut(&mut b);
        unsafe { FieldFfi::sys_sub(&A, ptr, &M, ptr) };
        assert_eq!(b, BigInt::from_u32(5));
    }

    #[test]
    fn mul_aliasing() {
        let mut a = A;
        let ptr = from_mut(&mut a);
        unsafe { FieldFfi::sys_mul(ptr, &B, &M, ptr) };
        assert_eq!(a, BigInt::from_u32(1)); // (3 * 5) mod 7

        let mut b = B;
        let ptr = from_mut(&mut b);
        unsafe { FieldFfi::sys_mul(&A, ptr, &M, ptr) };
        assert_eq!(b, BigInt::from_u32(1));
    }
}
