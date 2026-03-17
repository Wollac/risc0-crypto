mod ffi;
mod ops;

use crate::{
    BigInt,
    field::{Fp, FpConfig, Unreduced},
};
use bytemuck::TransparentWrapper;
use core::marker::PhantomData;

/// The base field of curve `C` (used for point coordinates).
pub type BaseField<C, const N: usize> = Fp<<C as SWCurveConfig<N>>::BaseFieldConfig, N>;

/// The scalar field of curve `C` (used for scalar multiplication).
pub type ScalarField<C, const N: usize> = Fp<<C as SWCurveConfig<N>>::ScalarFieldConfig, N>;

/// A trait that defines the configuration of a short Weierstrass curve `y² = x³ + ax + b`.
pub trait SWCurveConfig<const N: usize>: Send + Sync + 'static + Sized {
    type BaseFieldConfig: FpConfig<N>;
    type ScalarFieldConfig: FpConfig<N>;

    const COEFF_A: BaseField<Self, N>;
    const COEFF_B: BaseField<Self, N>;
    const GENERATOR: AffinePoint<Self, N>;

    /// Subgroup membership check. Default checks `[order]P == O`.
    /// Override for curves with cofactor 1 (where this is always true).
    fn is_in_correct_subgroup(p: &AffinePoint<Self, N>) -> bool {
        (p * Unreduced::wrap_ref(&Self::ScalarFieldConfig::MODULUS)).is_identity()
    }
}

/// Returns `2P` (point doubling).
pub trait Double {
    fn double(&self) -> Self;
}

/// Computes `2P` in-place.
pub trait DoubleAssign {
    fn double_assign(&mut self);
}

/// A point on a short Weierstrass curve in affine coordinates `(x, y)`.
///
/// `None` represents the point at infinity (identity). `Some([x, y])` stores the coordinates as
/// [`BigInt`] values.
///
/// Supports addition, negation, subtraction, doubling, and scalar multiplication via operator
/// overloads (`+`, `-`, `*`).
#[derive(educe::Educe)]
#[educe(Copy, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub struct AffinePoint<C: SWCurveConfig<N>, const N: usize> {
    coords: Option<[BigInt<N>; 2]>,
    _marker: PhantomData<C>,
}

impl<C: SWCurveConfig<N>, const N: usize> AffinePoint<C, N> {
    /// Curve parameters `[modulus, a, b]` for the FFI layer.
    const CURVE_PARAMS: [BigInt<N>; 3] =
        [C::BaseFieldConfig::MODULUS, C::COEFF_A.to_bigint(), C::COEFF_B.to_bigint()];

    /// The point at infinity (additive identity).
    pub const IDENTITY: Self = Self { coords: None, _marker: PhantomData };

    /// The curve's standard generator point.
    pub const GENERATOR: Self = C::GENERATOR;

    /// Creates a point from coordinates, returning `None` if the point is not on the curve or
    /// not in the correct subgroup.
    #[inline]
    pub fn new(x: BaseField<C, N>, y: BaseField<C, N>) -> Option<Self> {
        let p = Self::new_unchecked(x, y);
        if p.is_on_curve() && p.is_in_correct_subgroup() { Some(p) } else { None }
    }

    /// Creates a point from coordinates without validating on-curve or subgroup membership.
    #[inline]
    pub const fn new_unchecked(x: BaseField<C, N>, y: BaseField<C, N>) -> Self {
        Self { coords: Some([x.to_bigint(), y.to_bigint()]), _marker: PhantomData }
    }

    /// Returns `true` if this is the point at infinity.
    #[inline]
    #[must_use]
    pub const fn is_identity(&self) -> bool {
        self.coords.is_none()
    }

    /// Returns the `(x, y)` coordinates, or `None` if this is the identity.
    #[inline]
    pub const fn xy(&self) -> Option<(BaseField<C, N>, BaseField<C, N>)> {
        match self.coords {
            None => None,
            // SAFETY: coordinates from the EC syscall are canonical field elements.
            Some(ref c) => {
                Some(unsafe { (Fp::from_bigint_unchecked(c[0]), Fp::from_bigint_unchecked(c[1])) })
            }
        }
    }

    /// Checks `y² = x³ + ax + b` using field arithmetic.
    ///
    /// Uses [`Unreduced`] for intermediate results and checks canonicality only for the
    /// final comparison.
    #[must_use]
    pub fn is_on_curve(&self) -> bool {
        let Some(ref coords) = self.coords else {
            return true; // identity is on every curve
        };
        // zero-copy cast: &BigInt<N> -> &Unreduced<_, N>
        let x = Unreduced::wrap_ref(&coords[0]);
        let y = Unreduced::wrap_ref(&coords[1]);

        let lhs = y * y;

        let mut rhs = x * x;
        if !C::COEFF_A.is_zero() {
            rhs += &C::COEFF_A;
        }
        rhs *= x;
        rhs += &C::COEFF_B;

        lhs.check() == rhs.check()
    }

    /// Returns `true` if this point is in the prime-order subgroup.
    ///
    /// For curves with cofactor 1 this always returns `true`. For curves with a cofactor
    /// (e.g. BLS12-381) this checks `[order]P == O`.
    #[inline]
    #[must_use]
    pub fn is_in_correct_subgroup(&self) -> bool {
        C::is_in_correct_subgroup(self)
    }
}

impl<C: SWCurveConfig<N>, const N: usize> core::fmt::Debug for AffinePoint<C, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.xy() {
            Some((x, y)) => f.debug_struct("AffinePoint").field("x", &x).field("y", &y).finish(),
            None => write!(f, "AffinePoint(Identity)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{R0FieldConfig, field::Fp256};

    // --- Toy curve: y² = x³ + x + 1 over F_7, order 5 ---
    //
    // Points: O, (0,1), (2,5), (2,2), (0,6)
    // Group:  G=(0,1), 2G=(2,5), 3G=(2,2), 4G=(0,6), 5G=O

    enum FqConfig {}
    impl R0FieldConfig<8> for FqConfig {
        const MODULUS: BigInt<8> = BigInt::from_u32(7);
    }
    type Fq = Fp256<FqConfig>;

    enum FrConfig {}
    impl R0FieldConfig<8> for FrConfig {
        const MODULUS: BigInt<8> = BigInt::from_u32(5);
    }
    type Fr = Fp256<FrConfig>;

    enum Config {}
    impl SWCurveConfig<8> for Config {
        type BaseFieldConfig = FqConfig;
        type ScalarFieldConfig = FrConfig;
        const COEFF_A: Fq = Fq::from_u32(1);
        const COEFF_B: Fq = Fq::from_u32(1);
        const GENERATOR: Affine = AffinePoint::new_unchecked(Fq::from_u32(0), Fq::from_u32(1));
        fn is_in_correct_subgroup(_: &AffinePoint<Self, 8>) -> bool {
            true // cofactor = 1
        }
    }
    type Affine = AffinePoint<Config, 8>;

    fn pt(x: u32, y: u32) -> Affine {
        AffinePoint::new_unchecked(Fq::from_u32(x), Fq::from_u32(y))
    }

    #[test]
    fn point_validation() {
        let g = Affine::GENERATOR;
        let o = Affine::IDENTITY;

        assert!(g.is_on_curve());
        assert!(o.is_on_curve());
        assert!(!g.is_identity());
        assert!(o.is_identity());

        // all curve points are accepted
        assert!(Affine::new(Fq::from_u32(0), Fq::from_u32(1)).is_some());
        assert!(Affine::new(Fq::from_u32(2), Fq::from_u32(5)).is_some());
        assert!(Affine::new(Fq::from_u32(2), Fq::from_u32(2)).is_some());
        assert!(Affine::new(Fq::from_u32(0), Fq::from_u32(6)).is_some());

        // off-curve point is rejected
        assert!(Affine::new(Fq::from_u32(1), Fq::from_u32(1)).is_none());
    }

    #[test]
    fn point_addition() {
        let g = Affine::GENERATOR;
        let o = Affine::IDENTITY;

        // identity
        assert_eq!(&g + &o, g);
        assert_eq!(&o + &g, g);
        assert_eq!(&g - &o, g);
        assert!((&g - &g).is_identity());

        // doubling
        let two_g = g.double();
        assert_eq!(&g + &g, two_g);

        // commutativity
        assert_eq!(&g + &two_g, &two_g + &g);

        // negation
        assert!((-&o).is_identity());
        assert_eq!(-&g, pt(0, 6)); // -G = 4G (order 5)
        assert_eq!(&(-&g) + &g, o); // -G + G = O

        // subtraction: 3G - 2G = G
        let three_g = &g + &two_g;
        assert_eq!(&three_g - &two_g, g);

        // walk the full group: G, 2G, 3G, 4G, 5G=O
        assert_eq!(two_g, pt(2, 5)); // 2G
        assert_eq!(three_g, pt(2, 2)); // 3G
        assert_eq!(&two_g + &two_g, pt(0, 6)); // 4G
        assert!((&two_g + &pt(2, 2)).is_identity()); // 2G + 3G = 5G = O
    }

    #[test]
    fn scalar_mul() {
        let g = Affine::GENERATOR;

        assert_eq!(&g * &Fr::ONE, g);
        assert!((&g * &Fr::ZERO).is_identity());

        // [n]G = O (group order)
        let order = Unreduced::from_bigint(Fr::MODULUS);
        assert!((&g * &order).is_identity());

        // [2]G + [3]G = [5]G = O
        let two = Fr::from_u32(2);
        let three = Fr::from_u32(3);
        assert!((&(&g * &two) + &(&g * &three)).is_identity());

        // [2]G matches known point
        assert_eq!(&g * &two, pt(2, 5));
    }
}
