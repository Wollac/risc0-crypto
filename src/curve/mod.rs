mod ops;

use crate::{
    BigInt,
    field::{FieldArith, Fp, PrimeFieldConfig},
};
use core::marker::PhantomData;
use risc0_bigint2::ec;

/// Constructs an [`ec::AffinePoint`] in const context.
///
/// Workaround: `ec::AffinePoint::new_unchecked` is not const in `risc0_bigint2`.
const fn const_affine_point<const N: usize, C>(coords: [[u32; N]; 2]) -> ec::AffinePoint<N, C> {
    #[allow(unused)]
    struct Raw<const N: usize> {
        buffer: [[u32; N]; 2],
        identity: bool,
    }
    // SAFETY: ec::AffinePoint<N, C> has the layout { buffer, identity, PhantomData<C> }
    // where PhantomData<C> is a ZST, so it matches Raw<N>.
    assert!(
        size_of::<Raw<N>>() == size_of::<ec::AffinePoint<N, C>>(),
        "ec::AffinePoint layout mismatch - upstream type may have changed"
    );
    unsafe { core::mem::transmute_copy(&Raw { buffer: coords, identity: false }) }
}

/// The base field of curve `C` (used for point coordinates).
pub type BaseField<C, const N: usize> = Fp<<C as SWCurveConfig<N>>::BaseFieldConfig, N>;

/// The scalar field of curve `C` (used for scalar multiplication).
pub type ScalarField<C, const N: usize> = Fp<<C as SWCurveConfig<N>>::ScalarFieldConfig, N>;

/// A trait that defines the configuration of a short Weierstrass curve `y² = x³ + ax + b`.
pub trait SWCurveConfig<const N: usize>: Send + Sync + 'static + Sized
where
    [u32; N]: FieldArith,
{
    type BaseFieldConfig: PrimeFieldConfig<N>;
    type ScalarFieldConfig: PrimeFieldConfig<N>;

    const COEFF_A: BaseField<Self, N>;
    const COEFF_B: BaseField<Self, N>;
    const GENERATOR: AffinePoint<Self, N>;

    /// Subgroup membership check. Default checks `[order] * P == O`.
    /// Override for curves with cofactor 1 (where this is always true).
    fn is_in_correct_subgroup(p: &AffinePoint<Self, N>) -> bool {
        let mut result = AffinePoint::IDENTITY;
        p.inner.mul(&Self::ScalarFieldConfig::MODULUS.0, &mut result.inner);
        result.is_identity()
    }
}

// --- Bridge to bigint2 ---

// educe avoids unnecessary bounds on `C` that #[derive] would add.
#[derive(educe::Educe)]
#[educe(Debug, PartialEq, Eq, Hash)]
pub(crate) struct CurveBridge<C, const N: usize>(#[educe(Debug(ignore))] PhantomData<C>);

impl<C: SWCurveConfig<N>, const N: usize> ec::Curve<N> for CurveBridge<C, N>
where
    [u32; N]: FieldArith,
{
    const CURVE: &'static ec::WeierstrassCurve<N> = &ec::WeierstrassCurve::new(
        C::BaseFieldConfig::MODULUS.0,
        C::COEFF_A.to_limbs(),
        C::COEFF_B.to_limbs(),
    );
}

// --- AffinePoint ---

/// A point on a short Weierstrass curve in affine coordinates `(x, y)`.
///
/// Supports addition, subtraction, doubling, and scalar multiplication via operator
/// overloads (`+`, `-`, `*`) or explicit `_into` methods. The `_into` methods write
/// the result into `self`, avoiding temporaries.
#[derive(educe::Educe)]
#[educe(Copy, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub struct AffinePoint<C: SWCurveConfig<N>, const N: usize>
where
    [u32; N]: FieldArith,
{
    inner: ec::AffinePoint<N, CurveBridge<C, N>>,
}

impl<C: SWCurveConfig<N>, const N: usize> AffinePoint<C, N>
where
    [u32; N]: FieldArith,
{
    /// The point at infinity (additive identity).
    pub const IDENTITY: Self = Self { inner: ec::AffinePoint::IDENTITY };

    /// The curve's standard generator point.
    pub const GENERATOR: Self = C::GENERATOR;

    /// Creates a point from coordinates, returning `None` if the point is not on the
    /// curve or not in the correct subgroup.
    #[inline]
    pub fn new(x: BaseField<C, N>, y: BaseField<C, N>) -> Option<Self> {
        let p = Self::new_unchecked(x, y);
        if p.is_on_curve() && p.is_in_correct_subgroup() { Some(p) } else { None }
    }

    /// Creates a point from coordinates without validating on-curve or subgroup membership.
    #[inline]
    pub const fn new_unchecked(x: BaseField<C, N>, y: BaseField<C, N>) -> Self {
        Self { inner: const_affine_point([x.to_limbs(), y.to_limbs()]) }
    }

    /// Returns `true` if this is the point at infinity.
    #[inline]
    pub fn is_identity(&self) -> bool {
        self.inner.is_identity()
    }

    /// Returns the `(x, y)` coordinates, or `None` if this is the identity.
    #[inline]
    pub fn xy(&self) -> Option<(BaseField<C, N>, BaseField<C, N>)> {
        self.inner.as_u32s().map(|[x, y]| {
            (Fp::from_bigint_unchecked(BigInt(*x)), Fp::from_bigint_unchecked(BigInt(*y)))
        })
    }

    /// Checks `y² = x³ + ax + b` using field arithmetic.
    pub fn is_on_curve(&self) -> bool {
        let Some((x, y)) = self.xy() else {
            return true; // identity is on every curve
        };

        let mut t1 = Fp::ZERO;
        let mut t2 = Fp::ZERO;

        // unchecked: intermediate results that feed the checked final operations
        // t1 <- x^2
        t1.mul_unchecked(&x, &x);

        // When a=0 (e.g. BN254), the compiler eliminates the unused branch,
        // saving one modadd syscall by computing x^3 + b directly.
        if C::COEFF_A.is_zero() {
            // t2 <- x^3
            t2.mul_unchecked(&t1, &x);
            // t1 <- x^3 + b [RHS]
            t1.add(&t2, &C::COEFF_B);
            // t2 <- y^2 [LHS]
            t2.mul(&y, &y);
        } else {
            // t2 <- x^2 + a
            t2.add_unchecked(&t1, &C::COEFF_A);
            // t1 <- x(x^2 + a)
            t1.mul_unchecked(&t2, &x);
            // t2 <- (x^3 + ax) + b [RHS]
            t2.add(&t1, &C::COEFF_B);
            // t1 <- y^2 [LHS]
            t1.mul(&y, &y);
        }

        t1 == t2
    }

    /// Returns `true` if this point is in the prime-order subgroup.
    ///
    /// For curves with cofactor 1 this always returns `true`. For curves with a
    /// cofactor (e.g. BLS12-381) this checks `[order] * P == O`.
    #[inline]
    pub fn is_in_correct_subgroup(&self) -> bool {
        C::is_in_correct_subgroup(self)
    }

    /// Computes `self = a + b`.
    #[inline]
    pub fn add_into(&mut self, a: &Self, b: &Self) {
        a.inner.add(&b.inner, &mut self.inner);
    }

    /// Computes `self = 2 * a`.
    #[inline]
    pub fn double_into(&mut self, a: &Self) {
        a.inner.double(&mut self.inner);
    }

    /// Computes `self = a - b`.
    #[inline]
    pub fn sub_into(&mut self, a: &Self, b: &Self) {
        let Some((x, y)) = b.xy() else {
            *self = *a;
            return;
        };
        let mut neg_y = Fp::ZERO;
        neg_y.neg(&y);
        self.add_into(a, &Self::new_unchecked(x, neg_y));
    }

    /// Computes `self = [scalar] * a` (scalar multiplication).
    #[inline]
    pub fn mul_into(&mut self, a: &Self, scalar: &ScalarField<C, N>) {
        a.inner.mul(scalar.as_limbs(), &mut self.inner);
    }
}

impl<C: SWCurveConfig<N>, const N: usize> core::fmt::Debug for AffinePoint<C, N>
where
    [u32; N]: FieldArith,
{
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
    use crate::{
        BigInt,
        field::{Fp256, PrimeFieldConfig},
    };

    // --- Toy curve: y² = x³ + x + 1 over F_7, order 5 ---
    //
    // Points: O, (0,1), (2,5), (2,2), (0,6)
    // Group:  G=(0,1), 2G=(2,5), 3G=(2,2), 4G=(0,6), 5G=O

    enum FqConfig {}
    impl PrimeFieldConfig<8> for FqConfig {
        const MODULUS: BigInt<8> = BigInt::from_u32(7);
    }
    type Fq = Fp256<FqConfig>;

    enum FrConfig {}
    impl PrimeFieldConfig<8> for FrConfig {
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
    fn const_affine_point_matches_upstream() {
        let x = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let y = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20];
        let from_transmute: ec::AffinePoint<8, CurveBridge<Config, 8>> = const_affine_point([x, y]);
        let from_upstream = ec::AffinePoint::new_unchecked(x, y);
        assert_eq!(from_transmute, from_upstream);
    }

    #[test]
    fn point_validation() {
        let g = Affine::GENERATOR;
        let o = Affine::IDENTITY;

        assert!(g.is_on_curve());
        assert!(o.is_on_curve());
        assert!(!g.is_identity());
        assert!(o.is_identity());

        // All curve points are accepted
        assert!(Affine::new(Fq::from_u32(0), Fq::from_u32(1)).is_some());
        assert!(Affine::new(Fq::from_u32(2), Fq::from_u32(5)).is_some());
        assert!(Affine::new(Fq::from_u32(2), Fq::from_u32(2)).is_some());
        assert!(Affine::new(Fq::from_u32(0), Fq::from_u32(6)).is_some());

        // Off-curve point is rejected
        assert!(Affine::new(Fq::from_u32(1), Fq::from_u32(1)).is_none());
    }

    #[test]
    fn point_addition() {
        let g = Affine::GENERATOR;
        let o = Affine::IDENTITY;

        // Identity
        assert_eq!(g + o, g);
        assert_eq!(o + g, g);
        assert_eq!(g - o, g);
        assert!((g - g).is_identity());

        // Doubling
        let mut two_g = Affine::IDENTITY;
        two_g.double_into(&g);
        assert_eq!(g + g, two_g);

        // Commutativity
        assert_eq!(g + two_g, two_g + g);

        // Walk the full group: G, 2G, 3G, 4G, 5G=O
        assert_eq!(two_g, pt(2, 5)); // 2G
        assert_eq!(g + two_g, pt(2, 2)); // 3G
        assert_eq!(two_g + two_g, pt(0, 6)); // 4G
        assert!((two_g + pt(2, 2)).is_identity()); // 2G + 3G = 5G = O
    }

    #[test]
    fn scalar_mul() {
        let g = Affine::GENERATOR;

        assert_eq!(&g * &Fr::ONE, g);
        assert!((&g * &Fr::ZERO).is_identity());

        // [n]G = O (group order)
        let order = Fr::from_bigint_unchecked(FrConfig::MODULUS);
        assert!((&g * &order).is_identity());

        // [2]G + [3]G = [5]G = O
        let two = Fr::from_u32(2);
        let three = Fr::from_u32(3);
        assert!((&(&g * &two) + &(&g * &three)).is_identity());

        // [2]G matches known point
        assert_eq!(&g * &two, pt(2, 5));
    }
}
