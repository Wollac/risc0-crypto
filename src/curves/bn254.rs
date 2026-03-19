//! The BN254 (alt_bn128) curve used in Ethereum precompiles and SNARKs.
//!
//! - Equation: `y² = x³ + 3`
//! - Base field: 254-bit
//! - Cofactor: 1
//! - Spec: <https://eips.ethereum.org/EIPS/eip-197>

use crate::{AffinePoint, BigInt, Fp, R0CurveConfig, R0FieldConfig, bigint, fp};

// --- Base field (Fq): coordinates, modulus = q ---

pub enum FqConfig {}

impl R0FieldConfig<8> for FqConfig {
    const MODULUS: BigInt<8> =
        bigint!("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47");
}

pub type Fq = Fp<FqConfig, 8>;

// --- Scalar field (Fr): scalars, modulus = r ---

pub enum FrConfig {}

impl R0FieldConfig<8> for FrConfig {
    const MODULUS: BigInt<8> =
        bigint!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
}

pub type Fr = Fp<FrConfig, 8>;

// --- Curve config ---

pub enum Config {}

impl R0CurveConfig<8> for Config {
    type BaseFieldConfig = FqConfig;
    type ScalarFieldConfig = FrConfig;

    // G1 curve equation: y² = x³ + 3
    const COEFF_A: Fq = Fq::ZERO;
    const COEFF_B: Fq = fp!("0x3");

    const GENERATOR: Affine = AffinePoint::from_xy(fp!("0x1"), fp!("0x2"));

    fn is_in_correct_subgroup(_p: &AffinePoint<Self, 8>) -> bool {
        true // cofactor = 1
    }
}

pub type Affine = AffinePoint<Config, 8>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Unreduced;
    use rstest::rstest;

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

    /// Vyper/EIP-196 - ecmul test vectors for G=(1,2): verify [k]G == (x, y).
    #[rstest]
    #[case(
        fp!("0x2"),
        fp!("0x030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3"),
        fp!("0x15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4"),
    )]
    #[case(
        fp!("0x3"),
        fp!("0x0769bf9ac56bea3ff40232bcb1b6bd159315d84715b8e679f2d355961915abf0"),
        fp!("0x2ab799bee0489429554fdb7c8d086475319e63b40b9c5b57cdf1ff3dd9fe2261"),
    )]
    fn eip196_scalar_mul(#[case] k: Fr, #[case] expected_x: Fq, #[case] expected_y: Fq) {
        let result = &Affine::GENERATOR * &k;
        let (rx, ry) = result.xy().expect("result should not be identity");
        assert_eq!(rx, expected_x);
        assert_eq!(ry, expected_y);
    }
}
