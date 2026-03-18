#![doc = include_str!("../README.md")]
#![no_std]

pub mod bigint;
pub mod curve;
pub mod curves;
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

/// Creates an [`Fp<P,N>`] from a hex string literal.
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

pub use bigint::BigInt;
pub use curve::{AffinePoint, SWCurveConfig};
pub use field::{Fp, Fp256, Fp384, FpConfig, R0FieldConfig, Unreduced};
pub use modexp::{BitAccess, ModMul, modexp};
