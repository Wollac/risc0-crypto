//! The secp256k1 curve used in Bitcoin and Ethereum transaction signing.
//!
//! - Equation: `y² = x³ + 7`
//! - Base field: 256-bit
//! - Cofactor: 1
//! - Spec: <https://www.secg.org/sec2-v2.pdf> (section 2.4.1)

use crate::{AffinePoint, BigInt, Fp, R0FieldConfig, SWCurveConfig, bigint, fp};

// --- Base field (Fq): coordinates, modulus = p ---

pub enum FqConfig {}

impl R0FieldConfig<8> for FqConfig {
    const MODULUS: BigInt<8> =
        bigint!("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
}

pub type Fq = Fp<FqConfig, 8>;

// --- Scalar field (Fr): scalars, modulus = n ---

pub enum FrConfig {}

impl R0FieldConfig<8> for FrConfig {
    const MODULUS: BigInt<8> =
        bigint!("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
}

pub type Fr = Fp<FrConfig, 8>;

// --- Curve config ---

pub enum Config {}

impl SWCurveConfig<8> for Config {
    type BaseFieldConfig = FqConfig;
    type ScalarFieldConfig = FrConfig;

    // Curve equation: y^2 = x^3 + 7
    const COEFF_A: Fq = Fq::ZERO;
    const COEFF_B: Fq = fp!("0x7");

    const GENERATOR: Affine = AffinePoint::new_unchecked(
        fp!("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        fp!("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
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
        assert!((&Affine::GENERATOR * &order).is_identity());
    }

    /// noble-curves/secp256k1 test vectors
    #[rstest]
    #[case(
        fp!("0x2"),
        fp!("0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
        fp!("0x1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
    )]
    #[case(
        fp!("0x18ebbb95eed0e13"),
        fp!("0xa90cc3d3f3e146daadfc74ca1372207cb4b725ae708cef713a98edd73d99ef29"),
        fp!("0x5a79d6b289610c68bc3b47f3d72f9788a26a06868b4d8e433e1e2ad76fb7dc76"),
    )]
    fn noble_curves_scalar_mul(#[case] k: Fr, #[case] expected_x: Fq, #[case] expected_y: Fq) {
        let result = &Affine::GENERATOR * &k;
        let (rx, ry) = result.xy().expect("result should not be identity");
        assert_eq!(rx, expected_x);
        assert_eq!(ry, expected_y);
    }
}
