//! The Grumpkin curve, forming a cycle with BN254 for efficient recursive SNARKs.
//!
//! - Equation: `y² = x³ - 17`
//! - Base field: [BN254](super::bn254)'s scalar field (and vice versa)
//! - Cofactor: 1
//! - Spec: <https://aztecprotocol.github.io/aztec-connect/primitives.html> (section 2: Grumpkin)

use crate::{AffinePoint, CurveConfig, LIMBS_256, R0VMCurveOps, fp};

// --- Base field (Fq): coordinates, modulus = p (BN254 scalar field) ---
pub use super::bn254::{Fr as Fq, FrConfig as FqConfig};

// --- Scalar field (Fr): scalars, modulus = n (BN254 base field) ---
pub use super::bn254::{Fq as Fr, FqConfig as FrConfig};

// --- Curve config ---

pub enum Config {}

impl CurveConfig<LIMBS_256> for Config {
    type BaseFieldConfig = FqConfig;
    type ScalarFieldConfig = FrConfig;
    type Ops = R0VMCurveOps;

    // curve equation: y² = x³ - 17
    const COEFF_A: Fq = Fq::ZERO;
    const COEFF_B: Fq = fp!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffff0");

    const GENERATOR: Affine = AffinePoint::from_xy(
        fp!("0x1"),
        fp!("0x2cf135e7506a45d632d270d45f1181294833fc48d823f272c"),
    );

    #[inline(always)]
    fn is_in_correct_subgroup(_p: &AffinePoint<Self, LIMBS_256>) -> bool {
        true // cofactor = 1
    }
}

pub type Affine = AffinePoint<Config, LIMBS_256>;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    curve_sanity_tests!();

    /// noir-lang/noir bn254_blackbox_solver - scalar multiplication test vectors
    #[rstest]
    #[case(
        fp!("0x200000000000000000000000000000001"),
        fp!("0x0702ab9c7038eeecc179b4f209991bcb68c7cb05bf4c532d804ccac36199c9a9"),
        fp!("0x23f10e9e43a3ae8d75d24154e796aae12ae7af546716e8f81a2564f1b5814130"),
    )]
    fn noir_scalar_mul(#[case] k: Fr, #[case] expected_x: Fq, #[case] expected_y: Fq) {
        let result = &Affine::GENERATOR * &k;
        let (rx, ry) = result.xy().expect("result should not be identity");
        assert_eq!(rx, expected_x);
        assert_eq!(ry, expected_y);
    }
}
