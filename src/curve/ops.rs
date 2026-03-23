//! R0VM EC arithmetic backend.
//!
//! Provides [`R0VMCurveOps`], the R0VM [`CurveOps`](super::CurveOps) implementation backed by
//! direct `sys_bigint2` calls to R0VM EC circuits.
//!
//! The EC circuit blobs are copied from risc0-bigint2's source tree by `build.rs` - see that
//! file for why we bypass risc0-bigint2's EC API.

use super::{Coords, CurveConfig, CurveOps};
use crate::{BigInt, field::FieldConfig};
use bytemuck::TransparentWrapper;
use core::{mem::MaybeUninit, ptr};
use include_bytes_aligned::include_bytes_aligned;
use risc0_bigint2::ffi::{sys_bigint2_3, sys_bigint2_4};

/// Const pointer cast for a coordinate pair, guarded by [`TransparentWrapper`].
const fn cast_coords<T: TransparentWrapper<Inner>, Inner>(ptr: *const [T; 2]) -> *const [Inner; 2] {
    ptr.cast()
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

impl<C: CurveConfig<N>, const N: usize> CurveOps<C, N> for R0VMCurveOps {
    #[inline(always)]
    fn add_assign(a: &mut Coords<C, N>, b: &Coords<C, N>) {
        let ptr = cast_coords_mut(ptr::from_mut(a));
        // SAFETY: out aliases a per ec_add_raw's contract.
        unsafe { ec_add_raw(ptr, cast_coords(ptr::from_ref(b)), &C::CURVE_PARAMS, ptr) }
    }

    #[inline(always)]
    fn double_assign(a: &mut Coords<C, N>) {
        let ptr = cast_coords_mut(ptr::from_mut(a));
        // SAFETY: out aliases a per ec_double_raw's contract.
        unsafe { ec_double_raw(ptr, &C::CURVE_PARAMS, ptr) }
    }

    #[inline(always)]
    fn add(a: &Coords<C, N>, b: &Coords<C, N>) -> Coords<C, N> {
        let mut out = MaybeUninit::uninit();
        // SAFETY: ec_add_raw fully writes out before we assume_init.
        unsafe {
            ec_add_raw(
                cast_coords(ptr::from_ref(a)),
                cast_coords(ptr::from_ref(b)),
                &C::CURVE_PARAMS,
                cast_coords_mut(out.as_mut_ptr()),
            );
            out.assume_init()
        }
    }

    #[inline(always)]
    fn double(a: &Coords<C, N>) -> Coords<C, N> {
        let mut out = MaybeUninit::uninit();
        // SAFETY: ec_double_raw fully writes out before we assume_init.
        unsafe {
            ec_double_raw(
                cast_coords(ptr::from_ref(a)),
                &C::CURVE_PARAMS,
                cast_coords_mut(out.as_mut_ptr()),
            );
            out.assume_init()
        }
    }
}

// --- FFI layer (raw BigInt pointers) ---
//
// R0VM syscalls expect flat `u32` arrays. `[BigInt<N>; K]` is layout-compatible because
// `BigInt<N>` is `#[repr(transparent)]` over `[u32; N]`, so `[BigInt<N>; K]` is a contiguous
// `[u32; N * K]` in memory.

/// Computes `out = lhs + rhs` on the curve defined by `curve = [modulus, a, b]`.
///
/// Uses the chord rule where `lhs = (x₁, y₁)` and `rhs = (x₂, y₂)`:
///
/// ```text
/// λ  = (y₂ - y₁) / (x₂ - x₁)
/// x₃ = λ² - x₁ - x₂
/// y₃ = λ(x₁ - x₃) - y₁
/// ```
///
/// # Preconditions
///
/// - `x₁ != x₂` - when equal, the chord formula divides by zero.
/// - Neither point may be the identity (no affine representation).
///
/// # Safety
///
/// - `lhs` and `rhs` must point to readable, aligned `[BigInt<N>; 2]`.
/// - `out` must point to writable, aligned `[BigInt<N>; 2]` (need not be initialized).
/// - `out` may alias `lhs` or `rhs` - the FFI reads all inputs before writing.
#[inline(always)]
unsafe fn ec_add_raw<const N: usize>(
    lhs: *const [BigInt<N>; 2],
    rhs: *const [BigInt<N>; 2],
    curve: &[BigInt<N>; 3],
    out: *mut [BigInt<N>; 2],
) {
    const ADD_256: &[u8] = include_bytes_aligned!(4, concat!(env!("OUT_DIR"), "/ec_add_256.blob"));
    const ADD_384: &[u8] = include_bytes_aligned!(4, concat!(env!("OUT_DIR"), "/ec_add_384.blob"));

    let blob = match N {
        8 => ADD_256,
        12 => ADD_384,
        _ => panic!("unsupported EC width"),
    };
    // SAFETY: caller guarantees pointer validity and preconditions.
    unsafe {
        sys_bigint2_4(
            blob.as_ptr(),
            lhs.cast(),
            rhs.cast(),
            ptr::from_ref(curve).cast(),
            out.cast(),
        );
    }
}

/// Computes `out = [2]point` on the curve defined by `curve = [modulus, a, b]`.
///
/// Uses the tangent rule where `point = (x₁, y₁)`:
///
/// ```text
/// λ  = (3x₁² + a) / (2y₁)
/// x₃ = λ² - 2x₁
/// y₃ = λ(x₁ - x₃) - y₁
/// ```
///
/// # Preconditions
///
/// - `y₁ != 0` - when zero, the tangent formula divides by `2y₁`.
/// - The point may not be the identity (no affine representation).
///
/// # Safety
///
/// - `point` must point to readable, aligned `[BigInt<N>; 2]`.
/// - `out` must point to writable, aligned `[BigInt<N>; 2]` (need not be initialized).
/// - `out` may alias `point` - the FFI reads all inputs before writing.
#[inline(always)]
unsafe fn ec_double_raw<const N: usize>(
    point: *const [BigInt<N>; 2],
    curve: &[BigInt<N>; 3],
    out: *mut [BigInt<N>; 2],
) {
    const DOUBLE_256: &[u8] =
        include_bytes_aligned!(4, concat!(env!("OUT_DIR"), "/ec_double_256.blob"));
    const DOUBLE_384: &[u8] =
        include_bytes_aligned!(4, concat!(env!("OUT_DIR"), "/ec_double_384.blob"));

    let blob = match N {
        8 => DOUBLE_256,
        12 => DOUBLE_384,
        _ => panic!("unsupported EC width"),
    };
    // SAFETY: caller guarantees pointer validity and preconditions.
    unsafe {
        sys_bigint2_3(blob.as_ptr(), point.cast(), ptr::from_ref(curve).cast(), out.cast());
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
    fn ec_add_aliasing() {
        // G + 2G = 3G, aliasing lhs
        let mut a = G;
        let ptr = core::ptr::from_mut(&mut a);
        unsafe { ec_add_raw(ptr, &TWO_G, &CURVE, ptr) };
        assert_eq!(a, THREE_G);

        // 2G + G = 3G, aliasing lhs
        let mut a = TWO_G;
        let ptr = core::ptr::from_mut(&mut a);
        unsafe { ec_add_raw(ptr, &G, &CURVE, ptr) };
        assert_eq!(a, THREE_G);
    }

    #[test]
    fn ec_double_aliasing() {
        // [2]G = 2G, aliasing input
        let mut a = G;
        let ptr = core::ptr::from_mut(&mut a);
        unsafe { ec_double_raw(ptr, &CURVE, ptr) };
        assert_eq!(a, TWO_G);
    }
}
