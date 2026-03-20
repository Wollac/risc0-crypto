//! The secp384r1 (NIST P-384) curve used in TLS, certificate signing, and high-security
//! applications.
//!
//! - Equation: `y² = x³ - 3x + b`
//! - Base field: 384-bit
//! - Cofactor: 1
//! - Spec: <https://www.secg.org/sec2-v2.pdf> (section 2.5.1)

use crate::{
    AffinePoint, BigInt, CurveConfig, Fp, LIMBS_384, R0FieldConfig, R0VMCurveOps, bigint, fp,
};

// --- Base field (Fq): coordinates, modulus = p ---

pub enum FqConfig {}

impl R0FieldConfig<LIMBS_384> for FqConfig {
    const MODULUS: BigInt<LIMBS_384> = bigint!(
        "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"
    );
}

pub type Fq = Fp<FqConfig, LIMBS_384>;

// --- Scalar field (Fr): scalars, modulus = n ---

pub enum FrConfig {}

impl R0FieldConfig<LIMBS_384> for FrConfig {
    const MODULUS: BigInt<LIMBS_384> = bigint!(
        "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"
    );
}

pub type Fr = Fp<FrConfig, LIMBS_384>;

// --- Curve config ---

pub enum Config {}

impl CurveConfig<LIMBS_384> for Config {
    type BaseFieldConfig = FqConfig;
    type ScalarFieldConfig = FrConfig;
    type Ops = R0VMCurveOps;

    // curve equation: y² = x³ - 3x + b
    const COEFF_A: Fq = fp!(
        "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc"
    );
    const COEFF_B: Fq = fp!(
        "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"
    );

    const GENERATOR: Affine = AffinePoint::from_xy(
        fp!(
            "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"
        ),
        fp!(
            "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
        ),
    );

    #[inline(always)]
    fn is_in_correct_subgroup(_p: &AffinePoint<Self, LIMBS_384>) -> bool {
        true // cofactor = 1
    }
}

pub type Affine = AffinePoint<Config, LIMBS_384>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Unreduced;

    #[test]
    fn discriminant_is_nonzero() {
        // 4A³ + 27B² != 0 ensures the curve is non-singular
        let (a, b) = (Config::COEFF_A, Config::COEFF_B);
        let disc = &(&(&(&a * &a) * &a) * &Fq::from_u32(4)) + &(&(&b * &b) * &Fq::from_u32(27));
        assert!(!disc.is_zero());
    }

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
