//! The secp384r1 (NIST P-384) curve used in TLS, certificate signing, and high-security
//! applications.
//!
//! - Equation: `y² = x³ - 3x + b`
//! - Base field: 384-bit
//! - Cofactor: 1
//! - Spec: <https://www.secg.org/sec2-v2.pdf> (section 2.5.1)

use crate::{AffinePoint, BigInt, Fp, R0CurveConfig, R0FieldConfig, bigint, fp};

// --- Base field (Fq): coordinates, modulus = p ---

pub enum FqConfig {}

impl R0FieldConfig<12> for FqConfig {
    const MODULUS: BigInt<12> = bigint!(
        "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"
    );
}

pub type Fq = Fp<FqConfig, 12>;

// --- Scalar field (Fr): scalars, modulus = n ---

pub enum FrConfig {}

impl R0FieldConfig<12> for FrConfig {
    const MODULUS: BigInt<12> = bigint!(
        "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"
    );
}

pub type Fr = Fp<FrConfig, 12>;

// --- Curve config ---

pub enum Config {}

impl R0CurveConfig<12> for Config {
    type BaseFieldConfig = FqConfig;
    type ScalarFieldConfig = FrConfig;

    // curve equation: y² = x³ - 3x + b
    const COEFF_A: Fq = fp!(
        "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc"
    );
    const COEFF_B: Fq = fp!(
        "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"
    );

    const GENERATOR: Affine = AffinePoint::new_unchecked(
        fp!(
            "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"
        ),
        fp!(
            "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
        ),
    );

    fn is_in_correct_subgroup(_p: &AffinePoint<Self, 12>) -> bool {
        true // cofactor = 1
    }
}

pub type Affine = AffinePoint<Config, 12>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Unreduced;

    #[test]
    fn generator_is_valid() {
        assert!(Affine::GENERATOR.is_on_curve());
        assert!(Affine::GENERATOR.is_in_correct_subgroup());
    }

    #[test]
    fn mul_group_order_is_identity() {
        let order = Unreduced::from_bigint(FrConfig::MODULUS);
        assert!((&Affine::GENERATOR * &order).is_identity());
    }
}
