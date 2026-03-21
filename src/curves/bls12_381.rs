//! The BLS12-381 G1 curve used in Ethereum 2.0 BLS signatures and pairing-based protocols.
//!
//! - Equation: `y² = x³ + 4`
//! - Base field: 381-bit
//! - Cofactor: `0x396c8c005555e1568c00aaab0000aaab`
//! - Spec: <https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/>

use crate::{
    AffinePoint, BigInt, CurveConfig, Fp, LIMBS_384, R0FieldConfig, R0VMCurveOps, bigint, fp,
};

// --- Base field (Fq): coordinates, modulus = q (381 bits) ---

pub enum FqConfig {}

impl R0FieldConfig<LIMBS_384> for FqConfig {
    const MODULUS: BigInt<LIMBS_384> = bigint!(
        "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"
    );
}

pub type Fq = Fp<FqConfig, LIMBS_384>;

// --- Scalar field (Fr): scalars, modulus = r (255 bits, zero-padded to 12 limbs) ---

pub enum FrConfig {}

impl R0FieldConfig<LIMBS_384> for FrConfig {
    const MODULUS: BigInt<LIMBS_384> =
        bigint!("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
}

pub type Fr = Fp<FrConfig, LIMBS_384>;

// --- Curve config ---

pub enum Config {}

impl CurveConfig<LIMBS_384> for Config {
    type BaseFieldConfig = FqConfig;
    type ScalarFieldConfig = FrConfig;
    type Ops = R0VMCurveOps;

    // G1 curve equation: y² = x³ + 4
    const COEFF_A: Fq = Fq::ZERO;
    const COEFF_B: Fq = fp!("0x4");

    const GENERATOR: Affine = AffinePoint::from_xy(
        fp!(
            "0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        ),
        fp!(
            "0x8b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
        ),
    );

    const COFACTOR: &'static [u32] = &[0x0000aaab, 0x8c00aaab, 0x5555e156, 0x396c8c00];
}

pub type Affine = AffinePoint<Config, LIMBS_384>;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    curve_sanity_tests!();

    #[test]
    fn cofactor_matches_spec() {
        let expected = BigInt::<4>::from_hex("0x396c8c005555e1568c00aaab0000aaab");
        assert_eq!(Config::COFACTOR, &expected.0);
    }

    #[test]
    fn clear_cofactor_order_3_point() {
        // (0, 2) is on the curve (0³ + 4 = 4 = 2²) with order 3, not in G1
        let mut p = Affine::new(fp!("0x0"), fp!("0x2")).expect("should be on curve");
        assert!(!p.is_in_correct_subgroup());

        // pure torsion: 3 | h, so [h]P = O
        assert!(p.clear_cofactor().is_identity());

        // mixed order (G + torsion): clears to a non-trivial subgroup element
        p += &Affine::GENERATOR;
        assert!(!p.is_in_correct_subgroup());
        assert!(p.clear_cofactor().is_in_correct_subgroup());
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
