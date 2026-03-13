//! The BLS12-381 G1 curve used in Ethereum 2.0 BLS signatures and pairing-based protocols.
//!
//! - Equation: `y² = x³ + 4`
//! - Base field: 381-bit
//! - Cofactor: `0x396c8c005555e1568c00aaab0000aaab`
//! - Spec: <https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/>

use crate::{AffinePoint, BigInt, Fp, R0FieldConfig, SWCurveConfig, bigint, fp};

// --- Base field (Fq): coordinates, modulus = q (381 bits) ---

pub enum FqConfig {}

impl R0FieldConfig<12> for FqConfig {
    const MODULUS: BigInt<12> = bigint!(
        "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"
    );
}

pub type Fq = Fp<FqConfig, 12>;

// --- Scalar field (Fr): scalars, modulus = r (255 bits, zero-padded to 12 limbs) ---

pub enum FrConfig {}

impl R0FieldConfig<12> for FrConfig {
    const MODULUS: BigInt<12> =
        bigint!("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
}

pub type Fr = Fp<FrConfig, 12>;

// --- Curve config ---

pub enum Config {}

impl SWCurveConfig<12> for Config {
    type BaseFieldConfig = FqConfig;
    type ScalarFieldConfig = FrConfig;

    // G1 curve equation: y² = x³ + 4
    const COEFF_A: Fq = Fq::ZERO;
    const COEFF_B: Fq = fp!("0x4");

    const GENERATOR: Affine = AffinePoint::new_unchecked(
        fp!(
            "0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        ),
        fp!(
            "0x8b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
        ),
    );

    // cofactor != 1, use default: [n]P == O
}

pub type Affine = AffinePoint<Config, 12>;

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

    /// EIP-2537 - G1 scalar multiplication test vectors: verify [k]G == (x, y).
    #[rstest]
    #[rustfmt::skip]
    #[case(
        fp!("0x2"),
        fp!("0x0572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e"),
        fp!("0x166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28"),
    )]
    #[case(
        fp!("0x263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3"),
        fp!("0x0491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"),
        fp!("0x17cd7061575d3e8034fcea62adaa1a3bc38dca4b50e4c5c01d04dd78037c9cee914e17944ea99e7ad84278e5d49f36c4"),
    )]
    fn eip2537_scalar_mul(#[case] k: Fr, #[case] expected_x: Fq, #[case] expected_y: Fq) {
        let result = &Affine::GENERATOR * &k;
        let (rx, ry) = result.xy().expect("result should not be identity");
        assert_eq!(rx, expected_x);
        assert_eq!(ry, expected_y);
    }
}
