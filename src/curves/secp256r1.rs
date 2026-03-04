//! The secp256r1 (NIST P-256) curve used in TLS, WebAuthn, and passkeys.
//!
//! - Equation: `y² = x³ - 3x + b`
//! - Base field: 256-bit
//! - Cofactor: 1
//! - Spec: <https://www.secg.org/sec2-v2.pdf> (section 2.4.2)

use crate::{AffinePoint, BigInt, Fp, PrimeFieldConfig, SWCurveConfig, bigint, fp};

// --- Base field (Fq): coordinates, modulus = p ---

pub enum FqConfig {}

impl PrimeFieldConfig<8> for FqConfig {
    const MODULUS: BigInt<8> =
        bigint!("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
}

pub type Fq = Fp<FqConfig, 8>;

// --- Scalar field (Fr): scalars, modulus = n ---

pub enum FrConfig {}

impl PrimeFieldConfig<8> for FrConfig {
    const MODULUS: BigInt<8> =
        bigint!("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
}

pub type Fr = Fp<FrConfig, 8>;

// --- Curve config ---

pub enum Config {}

impl SWCurveConfig<8> for Config {
    type BaseFieldConfig = FqConfig;
    type ScalarFieldConfig = FrConfig;

    // Curve equation: y^2 = x^3 - 3x + b
    const COEFF_A: Fq = fp!("0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc");
    const COEFF_B: Fq = fp!("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");

    const GENERATOR: Affine = AffinePoint::new_unchecked(
        fp!("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
        fp!("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
    );

    fn is_in_correct_subgroup(_p: &AffinePoint<Self, 8>) -> bool {
        true // cofactor = 1
    }
}

pub type Affine = AffinePoint<Config, 8>;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn generator_is_valid() {
        assert!(Affine::GENERATOR.is_on_curve());
        assert!(Affine::GENERATOR.is_in_correct_subgroup());
    }

    #[test]
    fn mul_group_order_is_identity() {
        let order = Fr::from_bigint_unchecked(FrConfig::MODULUS);
        assert!((Affine::GENERATOR * order).is_identity());
    }

    /// RFC 5903 §8.1 - ECDH test vectors: verify [k]G == (x, y).
    #[rstest]
    #[case(
        fp!("0xc88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433"),
        fp!("0xdad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c3772581180"),
        fp!("0x5271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3"),
    )]
    #[case(
        fp!("0xc6ef9c5d78ae012a011164acb397ce2088685d8f06bf9be0b283ab46476bee53"),
        fp!("0xd12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf63"),
        fp!("0x56fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab"),
    )]
    fn rfc5903_scalar_mul(#[case] k: Fr, #[case] expected_x: Fq, #[case] expected_y: Fq) {
        let result = Affine::GENERATOR * k;
        let (rx, ry) = result.xy().expect("result should not be identity");
        assert_eq!(rx, expected_x);
        assert_eq!(ry, expected_y);
    }
}
