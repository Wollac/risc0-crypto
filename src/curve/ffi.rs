use crate::BigInt;
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
/// The caller **must** ensure `x₁ != x₂`. This covers two degenerate cases:
///
/// * **lhs == rhs** (doubling) - use [`ec_double_raw`] instead.
/// * **lhs == -rhs** (inverse) - the result is the identity; handle before calling.
///
/// When `x₁ == x₂` the formula divides by zero, which triggers an EQZ constraint failure
/// inside the bigint2 circuit.
///
/// Neither point may be the identity (the identity has no affine coordinates).
///
/// # Safety
///
/// * `lhs` and `rhs` must point to readable, aligned `[BigInt<N>; 2]`.
/// * `out` must point to writable, aligned `[BigInt<N>; 2]` (need not be initialized).
/// * `out` may alias `lhs` or `rhs` - the FFI reads all inputs before writing.
pub(crate) unsafe fn ec_add_raw<const N: usize>(
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
/// The caller **must** ensure `y₁ != 0`. When `y₁ == 0` the point has order 2 and
/// the double is the identity; handle before calling. The formula divides by `2y₁`,
/// so `y₁ == 0` triggers an EQZ constraint failure inside the bigint2 circuit.
///
/// The point may not be the identity (the identity has no affine coordinates).
///
/// # Safety
///
/// * `point` must point to readable, aligned `[BigInt<N>; 2]`.
/// * `out` must point to writable, aligned `[BigInt<N>; 2]` (need not be initialized).
/// * `out` may alias `point` - the FFI reads all inputs before writing.
pub(crate) unsafe fn ec_double_raw<const N: usize>(
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
    unsafe {
        sys_bigint2_3(blob.as_ptr(), point.cast(), ptr::from_ref(curve).cast(), out.cast());
    }
}
