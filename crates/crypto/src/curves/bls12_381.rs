//! The BLS12-381 G1 curve used in Ethereum 2.0 BLS signatures and pairing-based protocols.
//!
//! - Equation: `y² = x³ + 4`
//! - Base field: 381-bit
//! - Cofactor: `0x396c8c005555e1568c00aaab0000aaab`
//! - Spec: <https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/>

use crate::{
    AffinePoint, BigInt, CurveConfig, FieldConfig, Fp, LIMBS_384, R0VMCurveOps, R0VMFieldOps,
    bigint, fp,
};

// --- Base field (Fq): coordinates, modulus = q (381 bits) ---

pub enum FqConfig {}

impl FieldConfig<LIMBS_384> for FqConfig {
    const MODULUS: BigInt<LIMBS_384> = bigint!(
        "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"
    );
    type Ops = R0VMFieldOps;
}

pub type Fq = Fp<FqConfig, LIMBS_384>;

// --- Scalar field (Fr): scalars, modulus = r (255 bits, zero-padded to 12 limbs) ---

pub enum FrConfig {}

impl FieldConfig<LIMBS_384> for FrConfig {
    const MODULUS: BigInt<LIMBS_384> =
        bigint!("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    type Ops = R0VMFieldOps;
}

pub type Fr = Fp<FrConfig, LIMBS_384>;

// --- G1 subgroup check parameters ---

/// `|z|` for the BLS parameter `z = -0xd201000000010000` that generates the curve. In particular
/// `r = z⁴ - z² + 1`.
const Z_ABS: Fr = fp!("0xd201000000010000");

/// `β`, the primitive cube root of unity in `Fq` for which `φ(x, y) = (βx, y)` acts on G1 as
/// multiplication by `-z²`. The other root, `β²`, acts as `z² - 1`.
const BETA: Fq =
    fp!("0x5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe");

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

    /// Tests G1 membership with the curve endomorphism instead of checking `[r]P == O`.
    ///
    /// With `φ(x, y) = (βx, y)` for a cube root of unity `β`, and the BLS parameter `z`, a point
    /// `P` on the curve is in G1 if and only if
    ///
    /// ```text
    /// φ(P) == -[z²]P
    /// ```
    ///
    /// which takes two multiplications by the 64-bit `|z|` instead of one by the 255-bit `r`. It is
    /// sound because `φ² + φ + 1 = 0` on the curve and `r = z⁴ - z² + 1`, so the test implies
    /// `[r]P = O`. See [Scott][scott], [El Housni, Guillevic and Piellard][ehgp] and
    /// [EIP-2537][eip].
    ///
    /// [scott]: https://eprint.iacr.org/2021/1130
    /// [ehgp]: https://eprint.iacr.org/2022/352
    /// [eip]: https://github.com/ethereum/EIPs/blob/master/assets/eip-2537/fast_subgroup_checks.md
    fn is_in_correct_subgroup(p: &Affine) -> bool {
        let Some((x, y)) = p.xy_unverified() else {
            return true; // the identity is in every subgroup
        };

        // [z²]P as two multiplications by |z|
        let z2p = &(p * &Z_ABS) * &Z_ABS;
        let Some((z2x, z2y)) = z2p.xy_unverified() else {
            // -[z²]P = O cannot equal φ(P), which is not the identity. Not reachable for a point
            // on the curve, whose order is coprime to z.
            return false;
        };

        // φ(P) == -[z²]P  <=>  (βx, y) == (z2x, -z2y)
        (x * &BETA).check_is_eq(z2x) && (-z2y).check_is_eq(y)
    }
}

pub type Affine = AffinePoint<Config, LIMBS_384>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UnverifiedFp;
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

    /// The definition of G1 membership, `[r]P == O`, which the endomorphism test replaces.
    fn has_order_dividing_r(p: &Affine) -> bool {
        (p * &UnverifiedFp::from_bigint(FrConfig::MODULUS)).is_identity()
    }

    #[test]
    fn subgroup_check_parameters() {
        // β is a primitive cube root of unity
        assert_ne!(BETA, Fq::ONE);
        assert_eq!(&(&BETA * &BETA) * &BETA, Fq::ONE);

        // r = z⁴ - z² + 1. Both sides are below q, so equality in Fq is equality of integers.
        let z = Fq::from_bigint(Z_ABS.to_bigint()).unwrap();
        let r = Fq::from_bigint(FrConfig::MODULUS).unwrap();
        let z2 = &z * &z;
        assert_eq!(&(&(&z2 * &z2) - &z2) + &Fq::ONE, r);

        // φ acts on G1 as multiplication by -z²: φ(G) == -[z²]G. As G generates G1, this is
        // what makes the test accept every point of G1.
        let (gx, gy) = Affine::GENERATOR.xy().unwrap();
        let phi_g = Affine::new(&gx * &BETA, gy).expect("φ maps the curve to itself");
        assert_eq!(phi_g, -&(&Affine::GENERATOR * &(&Z_ABS * &Z_ABS)));
    }

    #[test]
    fn subgroup_check_matches_order_check() {
        assert!(Affine::IDENTITY.is_in_correct_subgroup());

        // multiples of the generator are in G1
        for k in [fp!("0x1"), fp!("0x2"), fp!("0x263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f2")]
        {
            let p = &Affine::GENERATOR * &k;
            assert!(has_order_dividing_r(&p));
            assert!(p.is_in_correct_subgroup());
        }

        // the points with these x-coordinates are on the curve but outside G1; clearing the
        // cofactor maps them into G1
        for x in [4, 5, 6] {
            let p = Affine::decompress(Fq::from_u32(x), false).expect("should be on curve");
            assert!(!has_order_dividing_r(&p));
            assert!(!p.is_in_correct_subgroup());

            let cleared = p.clear_cofactor();
            assert!(!cleared.is_identity());
            assert!(has_order_dividing_r(&cleared));
            assert!(cleared.is_in_correct_subgroup());
        }
    }

    /// EIP-2537 `bls_g1mul_g1_not_in_correct_subgroup` test vector: on the curve, outside G1.
    #[test]
    #[rustfmt::skip]
    fn eip2537_point_not_in_subgroup() {
        let x = fp!("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        let y = fp!("0x193fb7cedb32b2c3adc06ec11a96bc0d661869316f5e4a577a9f7c179593987beb4fb2ee424dbb2f5dd891e228b46c4a");

        let p = Affine::new(x, y).expect("should be on curve");
        assert!(!has_order_dividing_r(&p));
        assert!(!p.is_in_correct_subgroup());
        assert!(Affine::new_in_subgroup(x, y).is_none());
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
