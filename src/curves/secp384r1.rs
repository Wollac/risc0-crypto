//! The secp384r1 (NIST P-384) curve used in TLS, certificate signing, and high-security
//! applications.
//!
//! - Equation: `y² = x³ - 3x + b`
//! - Base field: 384-bit
//! - Cofactor: 1
//! - Spec: <https://www.secg.org/sec2-v2.pdf> (section 2.5.1)

use crate::{
    AffinePoint, BigInt, CurveConfig, FieldConfig, Fp, LIMBS_384, R0VMCurveOps, R0VMFieldOps,
    bigint, fp, ufp,
};

// --- Base field (Fq): coordinates, modulus = p ---

pub enum FqConfig {}

impl FieldConfig<LIMBS_384> for FqConfig {
    const MODULUS: BigInt<LIMBS_384> = bigint!(
        "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"
    );
    type Ops = R0VMFieldOps;
}

pub type Fq = Fp<FqConfig, LIMBS_384>;

// --- Scalar field (Fr): scalars, modulus = n ---

pub enum FrConfig {}

impl FieldConfig<LIMBS_384> for FrConfig {
    const MODULUS: BigInt<LIMBS_384> = bigint!(
        "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"
    );
    type Ops = R0VMFieldOps;
}

pub type Fr = Fp<FrConfig, LIMBS_384>;

// --- Curve config ---

pub enum Config {}

impl CurveConfig<LIMBS_384> for Config {
    type BaseField = Fq;
    type ScalarFieldConfig = FrConfig;
    type Ops = R0VMCurveOps;

    // curve equation: y² = x³ - 3x + b
    const COEFF_A: Fq = fp!(
        "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc"
    );
    const COEFF_B: Fq = fp!(
        "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"
    );

    const GENERATOR: Affine = AffinePoint::from_raw_coords([
        ufp!(
            "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"
        ),
        ufp!(
            "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
        ),
    ]);
    const COFACTOR: &'static [u32] = &[1];
}

pub type Affine = AffinePoint<Config, LIMBS_384>;

#[cfg(test)]
mod tests {
    use super::*;

    curve_sanity_tests!();
}
