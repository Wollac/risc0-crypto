//! R0VM EC arithmetic backend.
//!
//! This module connects [`R0CurveConfig`] to [`SWCurveConfig`] via a blanket impl backed by
//! direct `sys_bigint2` calls to R0VM EC circuits.
//!
//! The EC circuit blobs are copied from risc0-bigint2's source tree by `build.rs` - see that
//! file for why we bypass risc0-bigint2's EC API.
//!
//! Swapping to a different backend (e.g. host, different zkVM) means replacing this module - the
//! rest of the crate is backend-agnostic.

use super::{AffinePoint, R0CurveConfig, RawCoords, SWCurveConfig};
use crate::{BigInt, Fp, FpConfig};
use core::ptr;
use include_bytes_aligned::include_bytes_aligned;
use risc0_bigint2::ffi::{sys_bigint2_3, sys_bigint2_4};

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
/// * `x₁ != x₂` - when equal, the chord formula divides by zero.
/// * Neither point may be the identity (no affine representation).
///
/// # Safety
///
/// * `lhs` and `rhs` must point to readable, aligned `[BigInt<N>; 2]`.
/// * `out` must point to writable, aligned `[BigInt<N>; 2]` (need not be initialized).
/// * `out` may alias `lhs` or `rhs` - the FFI reads all inputs before writing.
#[inline(always)]
unsafe fn ec_add_raw<const N: usize>(
    lhs: *const RawCoords<N>,
    rhs: *const RawCoords<N>,
    curve: &[BigInt<N>; 3],
    out: *mut RawCoords<N>,
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
/// * `y₁ != 0` - when zero, the tangent formula divides by `2y₁`.
/// * The point may not be the identity (no affine representation).
///
/// # Safety
///
/// * `point` must point to readable, aligned `[BigInt<N>; 2]`.
/// * `out` must point to writable, aligned `[BigInt<N>; 2]` (need not be initialized).
/// * `out` may alias `point` - the FFI reads all inputs before writing.
#[inline(always)]
unsafe fn ec_double_raw<const N: usize>(
    point: *const RawCoords<N>,
    curve: &[BigInt<N>; 3],
    out: *mut RawCoords<N>,
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

impl<C: R0CurveConfig<N>, const N: usize> SWCurveConfig<N> for C
where
    <C as R0CurveConfig<N>>::BaseFieldConfig: FpConfig<N>,
    <C as R0CurveConfig<N>>::ScalarFieldConfig: FpConfig<N>,
{
    type BaseFieldConfig = <C as R0CurveConfig<N>>::BaseFieldConfig;
    type ScalarFieldConfig = <C as R0CurveConfig<N>>::ScalarFieldConfig;

    const COEFF_A: Fp<Self::BaseFieldConfig, N> = Self::COEFF_A;
    const COEFF_B: Fp<Self::BaseFieldConfig, N> = Self::COEFF_B;
    const GENERATOR: AffinePoint<Self, N> = Self::GENERATOR;

    fn is_in_correct_subgroup(p: &AffinePoint<Self, N>) -> bool {
        Self::is_in_correct_subgroup(p)
    }

    #[inline(always)]
    unsafe fn ec_add(a: *const RawCoords<N>, b: &RawCoords<N>, out: *mut RawCoords<N>) {
        // SAFETY: caller upholds SWCurveConfig's pointer contract; ec_add_raw forwards to FFI.
        unsafe { ec_add_raw(a, ptr::from_ref(b), &Self::CURVE_PARAMS, out) }
    }

    #[inline(always)]
    unsafe fn ec_double(a: *const RawCoords<N>, out: *mut RawCoords<N>) {
        // SAFETY: caller upholds SWCurveConfig's pointer contract; ec_double_raw forwards to FFI.
        unsafe { ec_double_raw(a, &Self::CURVE_PARAMS, out) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bigint, curves::secp256k1};

    type C = secp256k1::Config;

    // G, 2G, 3G for secp256k1 (from noble-curves test vectors)
    const G: RawCoords<8> = [
        bigint!("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        bigint!("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
    ];
    const TWO_G: RawCoords<8> = [
        bigint!("0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
        bigint!("0x1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
    ];
    const THREE_G: RawCoords<8> = [
        bigint!("0xf9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
        bigint!("0x388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672"),
    ];

    #[test]
    fn ec_add_aliasing() {
        // G + 2G = 3G, aliasing lhs
        let mut a = G;
        let ptr = core::ptr::from_mut(&mut a);
        unsafe { C::ec_add(ptr, &TWO_G, ptr) };
        assert_eq!(a, THREE_G);

        // 2G + G = 3G, aliasing lhs
        let mut a = TWO_G;
        let ptr = core::ptr::from_mut(&mut a);
        unsafe { C::ec_add(ptr, &G, ptr) };
        assert_eq!(a, THREE_G);
    }

    #[test]
    fn ec_double_aliasing() {
        // [2]G = 2G, aliasing input
        let mut a = G;
        let ptr = core::ptr::from_mut(&mut a);
        unsafe { C::ec_double(ptr, ptr) };
        assert_eq!(a, TWO_G);
    }
}
