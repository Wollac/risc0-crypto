#![doc = include_str!("../README.md")]
#![no_std]

pub mod bigint;
pub mod curve;
pub mod curves;
pub mod ecdsa;
pub mod field;
pub mod modexp;

/// Creates a [`BigInt`] from a hex string literal.
///
/// Panics if the value overflows `N` limbs.
///
/// ```
/// # use risc0_crypto::{BigInt, bigint};
/// const ONE: BigInt<8> = bigint!("0x1");
/// ```
#[macro_export]
macro_rules! bigint {
    ($hex:literal) => {
        $crate::BigInt::from_hex($hex)
    };
}

/// Creates an [`Fp`] from a hex string literal.
///
/// Panics if the value is `>= p`.
///
/// ```
/// # use risc0_crypto::{curves::secp256k1::Fq, fp};
/// const A: Fq = fp!("0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc");
/// ```
#[macro_export]
macro_rules! fp {
    ($hex:literal) => {
        match $crate::Fp::from_bigint($crate::bigint!($hex)) {
            Some(fp) => fp,
            None => panic!("field element must be less than the modulus"),
        }
    };
}

/// Creates an [`UnverifiedFp`] from a hex string literal. The value is NOT range-checked against
/// the modulus (consistent with `UnverifiedFp` semantics). Use `curve_sanity_tests!()` to
/// validate generators at test time.
#[macro_export]
macro_rules! ufp {
    ($hex:literal) => {
        $crate::UnverifiedFp::from_bigint($crate::bigint!($hex))
    };
}

/// Number of `u32` limbs for a 256-bit value.
pub const LIMBS_256: usize = 8;
/// Number of `u32` limbs for a 384-bit value.
pub const LIMBS_384: usize = 12;

pub use bigint::BigInt;
pub use curve::{AffinePoint, Coords, CurveConfig, CurveOps, PrimeCurveConfig, R0VMCurveOps};
pub use field::{
    Field, FieldConfig, FieldOps, Fp, Fp256, Fp384, PrimeField, R0VMFieldOps, UnverifiedField,
    UnverifiedFp,
};
pub use modexp::{BitAccess, ModMul, modexp};
