//! R0VM EC arithmetic backend.
//!
//! Provides [`R0VMCurveOps`], the R0VM [`CurveOps`] implementation backed by direct `sys_bigint2`
//! calls to R0VM EC circuits.
//!
//! The EC circuit blobs are copied from risc0-bigint2's source tree by `build.rs` - see that
//! file for why we bypass risc0-bigint2's EC API.

use super::{Coords, CurveConfig, CurveOps};
use crate::{BigInt, field::FieldConfig};
use bytemuck::TransparentWrapper;
use core::{mem::MaybeUninit, ptr};
use include_bytes_aligned::include_bytes_aligned;
use risc0_bigint2::ffi::{sys_bigint2_3, sys_bigint2_4};

/// Width-specific FFI dispatch for `risc0_bigint2` EC circuit syscalls.
///
/// Implemented only for [`BigInt<8>`] (256-bit) and [`BigInt<12>`] (384-bit).
///
/// # Safety
///
/// For every method:
/// - `out` must point to writable, aligned memory (need not be initialized).
/// - `out` must NOT alias inputs. EC circuits use multiple `EqualZeroOp` constraints whose
///   verify-program kWrite to the output arena corrupts subsequent kReads from an aliased input
///   arena during proving. Taking inputs by reference enforces non-aliasing at the call site.
trait CurveFfi: Sized {
    /// Chord rule: `out = lhs + rhs` on the curve `c = [modulus, a, b]`.
    unsafe fn sys_ec_add(lhs: &[Self; 2], rhs: &[Self; 2], c: &[Self; 3], out: *mut [Self; 2]);
    /// Tangent rule: `out = [2]point` on the curve `c = [modulus, a, b]`.
    unsafe fn sys_ec_double(point: &[Self; 2], c: &[Self; 3], out: *mut [Self; 2]);
}

impl CurveFfi for BigInt<8>
where
    Self: TransparentWrapper<[u32; 8]>,
{
    #[inline(always)]
    unsafe fn sys_ec_add(lhs: &[Self; 2], rhs: &[Self; 2], c: &[Self; 3], out: *mut [Self; 2]) {
        const BLOB: &[u8] = include_bytes_aligned!(4, concat!(env!("OUT_DIR"), "/ec_add_256.blob"));
        // SAFETY: BigInt<8> is repr(transparent) over [u32; 8] (bound above), so [BigInt<8>; K]
        // is a contiguous [u32; 8*K] - safe to cast to *const u32 for the syscall.
        unsafe {
            sys_bigint2_4(
                BLOB.as_ptr(),
                ptr::from_ref(lhs).cast(),
                ptr::from_ref(rhs).cast(),
                ptr::from_ref(c).cast(),
                out.cast(),
            )
        }
    }

    #[inline(always)]
    unsafe fn sys_ec_double(point: &[Self; 2], c: &[Self; 3], out: *mut [Self; 2]) {
        const BLOB: &[u8] =
            include_bytes_aligned!(4, concat!(env!("OUT_DIR"), "/ec_double_256.blob"));
        // SAFETY: see sys_ec_add
        unsafe {
            sys_bigint2_3(
                BLOB.as_ptr(),
                ptr::from_ref(point).cast(),
                ptr::from_ref(c).cast(),
                out.cast(),
            )
        }
    }
}

impl CurveFfi for BigInt<12>
where
    Self: TransparentWrapper<[u32; 12]>,
{
    #[inline(always)]
    unsafe fn sys_ec_add(lhs: &[Self; 2], rhs: &[Self; 2], c: &[Self; 3], out: *mut [Self; 2]) {
        const BLOB: &[u8] = include_bytes_aligned!(4, concat!(env!("OUT_DIR"), "/ec_add_384.blob"));
        // SAFETY: BigInt<12> is repr(transparent) over [u32; 12] (bound above), so [BigInt<12>; K]
        // is a contiguous [u32; 12*K] - safe to cast to *const u32 for the syscall.
        unsafe {
            sys_bigint2_4(
                BLOB.as_ptr(),
                ptr::from_ref(lhs).cast(),
                ptr::from_ref(rhs).cast(),
                ptr::from_ref(c).cast(),
                out.cast(),
            )
        }
    }

    #[inline(always)]
    unsafe fn sys_ec_double(point: &[Self; 2], c: &[Self; 3], out: *mut [Self; 2]) {
        const BLOB: &[u8] =
            include_bytes_aligned!(4, concat!(env!("OUT_DIR"), "/ec_double_384.blob"));
        // SAFETY: see sys_ec_add
        unsafe {
            sys_bigint2_3(
                BLOB.as_ptr(),
                ptr::from_ref(point).cast(),
                ptr::from_ref(c).cast(),
                out.cast(),
            )
        }
    }
}

/// Reference cast for a coordinate pair, guarded by [`TransparentWrapper`].
///
/// # Safety
///
/// `[T; 2]` and `[Inner; 2]` have identical layout because `T: TransparentWrapper<Inner>`.
const fn cast_coords_ref<T: TransparentWrapper<Inner>, Inner>(r: &[T; 2]) -> &[Inner; 2] {
    unsafe { &*ptr::from_ref(r).cast() }
}

/// Mutable pointer cast for a coordinate pair, guarded by [`TransparentWrapper`].
const fn cast_coords_mut<T: TransparentWrapper<Inner>, Inner>(ptr: *mut [T; 2]) -> *mut [Inner; 2] {
    ptr.cast()
}

/// R0VM backend for EC arithmetic, backed by `sys_bigint2` FFI calls.
pub enum R0VMCurveOps {}

/// Compile-time curve parameters `[modulus, a, b]` derived from any [`CurveConfig`].
trait CurveParams<const N: usize> {
    const CURVE_PARAMS: [BigInt<N>; 3];
}

impl<const N: usize, C: CurveConfig<N>> CurveParams<N> for C {
    const CURVE_PARAMS: [BigInt<N>; 3] =
        [C::BaseFieldConfig::MODULUS, C::COEFF_A.to_bigint(), C::COEFF_B.to_bigint()];
}

impl<C: CurveConfig<N>, const N: usize> CurveOps<C, N> for R0VMCurveOps
where
    BigInt<N>: CurveFfi,
{
    #[inline]
    fn add_into(a: &Coords<C, N>, b: &Coords<C, N>, out: &mut Coords<C, N>) {
        // SAFETY: out is &mut so it cannot alias a or b (Rust borrow rules).
        unsafe {
            CurveFfi::sys_ec_add(
                cast_coords_ref(a),
                cast_coords_ref(b),
                &C::CURVE_PARAMS,
                cast_coords_mut(ptr::from_mut(out)),
            );
        }
    }

    #[inline]
    fn double_into(a: &Coords<C, N>, out: &mut Coords<C, N>) {
        // SAFETY: out is &mut so it cannot alias a (Rust borrow rules).
        unsafe {
            CurveFfi::sys_ec_double(
                cast_coords_ref(a),
                &C::CURVE_PARAMS,
                cast_coords_mut(ptr::from_mut(out)),
            );
        }
    }

    #[inline]
    fn add(a: &Coords<C, N>, b: &Coords<C, N>) -> Coords<C, N> {
        let mut out = MaybeUninit::uninit();
        // SAFETY: out is fully written by sys_ec_add before assume_init.
        unsafe {
            CurveFfi::sys_ec_add(
                cast_coords_ref(a),
                cast_coords_ref(b),
                &C::CURVE_PARAMS,
                cast_coords_mut(out.as_mut_ptr()),
            );
            out.assume_init()
        }
    }

    #[inline]
    fn double(a: &Coords<C, N>) -> Coords<C, N> {
        let mut out = MaybeUninit::uninit();
        // SAFETY: out is fully written by sys_ec_double before assume_init.
        unsafe {
            CurveFfi::sys_ec_double(
                cast_coords_ref(a),
                &C::CURVE_PARAMS,
                cast_coords_mut(out.as_mut_ptr()),
            );
            out.assume_init()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bigint, curves::secp256k1};

    type C = secp256k1::Config;

    /// Curve parameters for direct FFI calls.
    const CURVE: [BigInt<8>; 3] = C::CURVE_PARAMS;

    // G, 2G, 3G for secp256k1 (from noble-curves test vectors)
    const G: [BigInt<8>; 2] = [
        bigint!("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        bigint!("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
    ];
    const TWO_G: [BigInt<8>; 2] = [
        bigint!("0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
        bigint!("0x1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
    ];
    const THREE_G: [BigInt<8>; 2] = [
        bigint!("0xf9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
        bigint!("0x388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672"),
    ];

    #[test]
    fn ec_add_non_aliased() {
        let mut out = G;
        unsafe { CurveFfi::sys_ec_add(&G, &TWO_G, &CURVE, &mut out) };
        assert_eq!(out, THREE_G);

        let mut out = G;
        unsafe { CurveFfi::sys_ec_add(&TWO_G, &G, &CURVE, &mut out) };
        assert_eq!(out, THREE_G);
    }

    #[test]
    fn ec_double_non_aliased() {
        let mut out = G;
        unsafe { CurveFfi::sys_ec_double(&G, &CURVE, &mut out) };
        assert_eq!(out, TWO_G);
    }
}
