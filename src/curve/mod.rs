mod ops;

pub use ops::R0VMCurveOps;

use crate::{
    BitAccess,
    field::{FieldConfig, Fp, UnverifiedFp},
};
use bytemuck::TransparentWrapper;
use core::{
    hash::{Hash, Hasher},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

/// The base field of curve `C` (used for point coordinates).
pub type BaseField<C, const N: usize> = Fp<<C as CurveConfig<N>>::BaseFieldConfig, N>;

/// The scalar field of curve `C` (used for scalar multiplication).
pub type ScalarField<C, const N: usize> = Fp<<C as CurveConfig<N>>::ScalarFieldConfig, N>;

/// Unverified base field element of curve `C` (used for intermediate coordinate arithmetic).
type UnverifiedBaseField<C, const N: usize> =
    UnverifiedFp<<C as CurveConfig<N>>::BaseFieldConfig, N>;

/// An `[x, y]` coordinate pair as unverified base field elements. May not be in `[0, p)`.
pub type Coords<C, const N: usize> = [UnverifiedBaseField<C, N>; 2];

/// EC arithmetic operations for a short Weierstrass curve.
///
/// All methods are safe - unsafe FFI is contained within the backend implementation. The
/// `_assign` / in-place variants are the required primitives; non-assign variants have default
/// implementations that copy and delegate.
pub trait CurveOps<C: CurveConfig<N>, const N: usize>: Send + Sync + 'static {
    /// Computes `a + b` in place (chord rule).
    ///
    /// Where `a = (x₁, y₁)` and `b = (x₂, y₂)`:
    ///
    /// ```text
    /// λ  = (y₂ - y₁) / (x₂ - x₁)
    /// x₃ = λ² - x₁ - x₂
    /// y₃ = λ(x₁ - x₃) - y₁
    /// ```
    ///
    /// # Preconditions
    ///
    /// The caller must ensure `x₁ != x₂`. When `x₁ == x₂` the chord formula divides by zero.
    /// Handle same-x cases (doubling, inverse) before calling.
    fn add_assign(a: &mut Coords<C, N>, b: &Coords<C, N>);

    /// Computes `[2]a` in place (tangent rule).
    ///
    /// Where `a = (x₁, y₁)`:
    ///
    /// ```text
    /// λ  = (3x₁² + a) / (2y₁)
    /// x₃ = λ² - 2x₁
    /// y₃ = λ(x₁ - x₃) - y₁
    /// ```
    ///
    /// # Preconditions
    ///
    /// The caller must ensure `y != 0`. When `y == 0` the tangent formula divides by `2y`.
    fn double_assign(a: &mut Coords<C, N>);

    /// Non-assign version of [`add_assign`](Self::add_assign). Same preconditions apply.
    #[inline]
    fn add(a: &Coords<C, N>, b: &Coords<C, N>) -> Coords<C, N> {
        let mut r = *a;
        Self::add_assign(&mut r, b);
        r
    }

    /// Non-assign version of [`double_assign`](Self::double_assign). Same preconditions
    /// apply.
    #[inline]
    fn double(a: &Coords<C, N>) -> Coords<C, N> {
        let mut r = *a;
        Self::double_assign(&mut r);
        r
    }
}

/// EC arithmetic for a short Weierstrass curve `y² = x³ + ax + b`.
///
/// Implement this trait to define a new curve. EC operations are delegated to the associated
/// [`Ops`](Self::Ops) type, which implements [`CurveOps`].
pub trait CurveConfig<const N: usize>: Sized + Send + Sync + 'static {
    /// Base field config (coordinates).
    type BaseFieldConfig: FieldConfig<N>;
    /// Scalar field config (scalar multiplication).
    type ScalarFieldConfig: FieldConfig<N>;
    /// EC arithmetic backend. Use [`R0VMCurveOps`] for the R0VM target.
    type Ops: CurveOps<Self, N>;

    /// Coefficient `a` in `y² = x³ + ax + b`.
    const COEFF_A: BaseField<Self, N>;
    /// Coefficient `b` in `y² = x³ + ax + b`.
    const COEFF_B: BaseField<Self, N>;
    /// Standard generator point.
    const GENERATOR: AffinePoint<Self, N>;
    /// Cofactor `h` of the curve group as little-endian `u32` limbs.
    ///
    /// A `&'static [u32]` slice rather than `BigInt<N>` because the cofactor is a plain integer
    /// with curve-dependent size - not a field element. Using a slice avoids const generic
    /// proliferation on the trait and feeds directly into scalar multiplication.
    const COFACTOR: &'static [u32];

    /// Subgroup membership check. Default returns `true` for cofactor-1 curves, otherwise
    /// checks `[order]P == O`. Override for curves with more efficient subgroup checks.
    fn is_in_correct_subgroup(p: &AffinePoint<Self, N>) -> bool {
        if cofactor::is_one::<Self, _>() {
            return true;
        }
        let order = UnverifiedFp::wrap_ref(&Self::ScalarFieldConfig::MODULUS);
        (p * order).is_identity()
    }
}

mod cofactor {
    use super::CurveConfig;
    use crate::BitAccess;

    /// Returns `true` if the cofactor of curve `C` is 1.
    pub(super) fn is_one<C: CurveConfig<N>, const N: usize>() -> bool {
        C::COFACTOR[0] == 1 && C::COFACTOR.iter().skip(1).all(|&e| e == 0)
    }

    /// Returns `true` if the cofactor of curve `C` is odd.
    pub(super) const fn is_odd<C: CurveConfig<N>, const N: usize>() -> bool {
        C::COFACTOR[0] & 1 != 0
    }

    /// [`BitAccess`] adapter for LE `u32` cofactor limbs.
    /// Private newtype keeps the impl out of the public API.
    pub(super) struct Bits<'a>(pub &'a [u32]);

    impl BitAccess for Bits<'_> {
        #[inline]
        fn bits(&self) -> usize {
            for i in (0..self.0.len()).rev() {
                if self.0[i] != 0 {
                    return (i + 1) * 32 - self.0[i].leading_zeros() as usize;
                }
            }
            0
        }

        #[inline]
        fn bit(&self, i: usize) -> bool {
            let limb = i / 32;
            limb < self.0.len() && self.0[limb] & (1 << (i % 32)) != 0
        }
    }
}

/// A point on a short Weierstrass curve in affine coordinates `(x, y)`.
///
/// # Invariant
///
/// Every `AffinePoint` satisfies the curve equation `y² = x³ + ax + b` (or is the identity).
/// This is enforced by the public constructors: [`new`](Self::new) validates on-curve,
/// [`new_in_subgroup`](Self::new_in_subgroup) additionally validates subgroup membership, and
/// [`new_unchecked`](Self::new_unchecked) is `unsafe` requiring the caller to guarantee it.
/// Arithmetic operations preserve the invariant by construction.
///
/// Subgroup membership is *not* enforced - use [`new_in_subgroup`](Self::new_in_subgroup) or
/// [`is_in_correct_subgroup`](Self::is_in_correct_subgroup) to check explicitly.
///
/// Supports addition, negation, subtraction, doubling, and scalar multiplication via operator
/// overloads (`+`, `-`, `*`).
#[derive(educe::Educe)]
#[educe(Copy, Clone)]
#[must_use]
pub struct AffinePoint<C: CurveConfig<N>, const N: usize> {
    /// `None` represents the point at infinity (identity). Coordinates are canonical (`< p`)
    /// after construction; arithmetic operations may produce non-canonical results. Access via
    /// `xy()` / `xy_ref()` (check - asserts canonical) or `xy_unverified()` (defers to caller).
    coords: Option<Coords<C, N>>,
}

// --- Constants and constructors ---

impl<C: CurveConfig<N>, const N: usize> AffinePoint<C, N> {
    /// The point at infinity (additive identity).
    pub const IDENTITY: Self = Self { coords: None };

    /// The curve's standard generator point.
    pub const GENERATOR: Self = C::GENERATOR;

    /// Creates a point from coordinates, returning `None` if the point is not on the curve.
    ///
    /// Does not check subgroup membership - use [`new_in_subgroup`](Self::new_in_subgroup) for
    /// that. For curves with cofactor 1, `new` and `new_in_subgroup` are equivalent.
    pub fn new(x: BaseField<C, N>, y: BaseField<C, N>) -> Option<Self> {
        let p = Self::from_xy(x, y);
        if p.is_on_curve() { Some(p) } else { None }
    }

    /// Creates a point from coordinates, returning `None` if the point is not on the curve or
    /// not in the correct subgroup.
    pub fn new_in_subgroup(x: BaseField<C, N>, y: BaseField<C, N>) -> Option<Self> {
        let p = Self::new(x, y)?;
        if p.is_in_correct_subgroup() { Some(p) } else { None }
    }

    /// Creates a point from coordinates without validating on-curve or subgroup membership.
    ///
    /// # Safety
    ///
    /// The caller must ensure the point `(x, y)` satisfies the curve equation
    /// `y² = x³ + ax + b`. Passing an off-curve point to arithmetic operations is undefined
    /// behavior at the R0VM circuit level.
    #[inline]
    pub const unsafe fn new_unchecked(x: BaseField<C, N>, y: BaseField<C, N>) -> Self {
        Self::from_xy(x, y)
    }

    /// Internal unchecked constructor. The crate upholds the on-curve invariant via:
    /// - hardcoded generator coordinates (validated by tests)
    /// - arithmetic operations that preserve on-curve by construction
    #[inline]
    pub(crate) const fn from_xy(x: BaseField<C, N>, y: BaseField<C, N>) -> Self {
        Self {
            coords: Some([
                UnverifiedFp::from_bigint(x.to_bigint()),
                UnverifiedFp::from_bigint(y.to_bigint()),
            ]),
        }
    }

    /// Returns `true` if this is the point at infinity.
    #[inline]
    pub const fn is_identity(&self) -> bool {
        self.coords.is_none()
    }

    /// Returns the `(x, y)` coordinates as [`Fp`] values, or `None` for the identity.
    ///
    /// Panics if either coordinate is not in `[0, p)`.
    #[inline(always)]
    pub const fn xy(&self) -> Option<(BaseField<C, N>, BaseField<C, N>)> {
        match &self.coords {
            None => None,
            &Some([x, y]) => Some((x.check(), y.check())),
        }
    }

    /// Returns the `(x, y)` coordinates as [`Fp`] references, or `None` for the identity.
    /// Zero-cost - no copy, just a pointer cast.
    ///
    /// Panics if either coordinate is not in `[0, p)`.
    #[inline(always)]
    pub const fn xy_ref(&self) -> Option<(&BaseField<C, N>, &BaseField<C, N>)> {
        match &self.coords {
            None => None,
            Some([x, y]) => Some((x.check_ref(), y.check_ref())),
        }
    }

    /// Returns the `(x, y)` coordinates as [`UnverifiedFp`] references, or `None` for the
    /// identity.
    ///
    /// Use this for intermediate arithmetic where canonicality checks can be deferred.
    #[inline(always)]
    pub const fn xy_unverified(
        &self,
    ) -> Option<(&UnverifiedBaseField<C, N>, &UnverifiedBaseField<C, N>)> {
        match &self.coords {
            None => None,
            Some([x, y]) => Some((x, y)),
        }
    }

    /// Checks whether `(x, y)` satisfies the curve equation `y² = x³ + ax + b`.
    #[must_use]
    pub fn is_on_curve(&self) -> bool {
        let Some([x, y]) = &self.coords else {
            return true; // identity is on every curve
        };

        let lhs = y * y;

        let mut rhs = x * x;
        if !C::COEFF_A.is_zero() {
            rhs += &C::COEFF_A;
        }
        rhs *= x;
        rhs += &C::COEFF_B;

        lhs.check_is_eq(&rhs)
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

    /// Computes `[2]self`.
    #[inline]
    pub fn double(&self) -> Self {
        let Some(a_xy) = &self.coords else {
            return Self::IDENTITY;
        };
        // y == 0 is impossible for on-curve points when the cofactor is odd (no 2-torsion)
        if !cofactor::is_odd::<C, _>() {
            // raw is_zero() handles the honest case (y == 0); a dishonest non-canonical
            // zero (y > 0 but y == 0 mod p) needs no check since ec_double panics on y == 0
            if a_xy[1].as_bigint().is_zero() {
                return Self::IDENTITY;
            }
        }
        Self { coords: Some(C::Ops::double(a_xy)) }
    }

    /// Computes `[2]self` in place.
    #[inline]
    pub fn double_assign(&mut self) {
        let Some(a_xy) = &mut self.coords else {
            return;
        };
        // y == 0 is impossible for on-curve points when the cofactor is odd (no 2-torsion)
        if !cofactor::is_odd::<C, _>() {
            // raw is_zero() handles the honest case (y == 0); a dishonest non-canonical
            // zero (y > 0 but y == 0 mod p) needs no check since ec_double panics on y == 0
            if a_xy[1].as_bigint().is_zero() {
                self.coords = None;
                return;
            }
        }
        C::Ops::double_assign(a_xy);
    }

    /// Maps this point to the prime-order subgroup by computing `[h]self`.
    ///
    /// For cofactor-1 curves this is a no-op.
    #[inline]
    pub fn clear_cofactor(&self) -> Self {
        if cofactor::is_one::<C, _>() {
            return *self;
        }
        self.scalar_mul(&cofactor::Bits(C::COFACTOR))
    }

    /// Computes `[scalar]self` via MSB-first double-and-add.
    ///
    /// Works for any point on the curve regardless of subgroup. The scalar is interpreted as an
    /// unsigned integer and may be `>= n` (the group order).
    fn scalar_mul(&self, scalar: &(impl BitAccess + ?Sized)) -> Self {
        let n = scalar.bits();
        if self.is_identity() || n == 0 {
            return Self::IDENTITY;
        }
        let mut acc = *self;
        for i in (0..n - 1).rev() {
            acc.double_assign();
            if scalar.bit(i) {
                acc.add_assign(self);
            }
        }
        acc
    }
}

// --- Std trait impls ---

impl<C: CurveConfig<N>, const N: usize> core::fmt::Debug for AffinePoint<C, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.coords {
            None => write!(f, "AffinePoint(Identity)"),
            Some([x, y]) => f.debug_struct("AffinePoint").field("x", x).field("y", y).finish(),
        }
    }
}

/// Compares canonical coordinates. Panics if either point has non-canonical coordinates.
impl<C: CurveConfig<N>, const N: usize> PartialEq for AffinePoint<C, N> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.xy_ref() == other.xy_ref()
    }
}

impl<C: CurveConfig<N>, const N: usize> Eq for AffinePoint<C, N> {}

/// Hashes canonical coordinates. Panics if the point has non-canonical coordinates.
impl<C: CurveConfig<N>, const N: usize> Hash for AffinePoint<C, N> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.xy_ref().hash(state);
    }
}

// --- Operator impls ---

impl<C: CurveConfig<N>, const N: usize> Neg for &AffinePoint<C, N> {
    type Output = AffinePoint<C, N>;

    #[inline]
    fn neg(self) -> AffinePoint<C, N> {
        let mut result = *self;
        if let Some(a_xy) = &mut result.coords {
            a_xy[1].neg_in_place();
        }
        result
    }
}

impl<C: CurveConfig<N>, const N: usize> Add for &AffinePoint<C, N> {
    type Output = AffinePoint<C, N>;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        match (&self.coords, &rhs.coords) {
            (_, None) => *self,
            (None, _) => *rhs,
            // same x: doubling (P + P) or cancellation (P + (-P))
            // sound if non-canonical: ec_add divides by x2 - x1, circuit fails on x2 - x1 == 0
            (Some(a_xy), Some(b_xy)) if a_xy[0].raw_eq(&b_xy[0]) => {
                if a_xy[1].check_is_eq(&b_xy[1]) { self.double() } else { AffinePoint::IDENTITY }
            }
            (Some(a_xy), Some(b_xy)) => AffinePoint { coords: Some(C::Ops::add(a_xy, b_xy)) },
        }
    }
}

impl<C: CurveConfig<N>, const N: usize> AddAssign<&Self> for AffinePoint<C, N> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        match (&mut self.coords, &rhs.coords) {
            (_, None) => {}
            (None, Some(_)) => *self = *rhs,
            // same x: doubling (P + P) or cancellation (P + (-P))
            // sound if non-canonical: ec_add divides by x2 - x1, circuit fails on x2 - x1 == 0
            (Some(a_xy), Some(b_xy)) if a_xy[0].raw_eq(&b_xy[0]) => {
                if a_xy[1].check_is_eq(&b_xy[1]) {
                    self.double_assign();
                } else {
                    self.coords = None;
                }
            }
            (Some(a_xy), Some(b_xy)) => {
                C::Ops::add_assign(a_xy, b_xy);
            }
        }
    }
}

impl<C: CurveConfig<N>, const N: usize> Sub for &AffinePoint<C, N> {
    type Output = AffinePoint<C, N>;

    #[inline]
    fn sub(self, rhs: Self) -> AffinePoint<C, N> {
        self + &(-rhs)
    }
}

impl<C: CurveConfig<N>, const N: usize> SubAssign<&Self> for AffinePoint<C, N> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        self.add_assign(&(-rhs));
    }
}

impl<C: CurveConfig<N>, const N: usize, T: AsRef<UnverifiedFp<C::ScalarFieldConfig, N>>> Mul<&T>
    for &AffinePoint<C, N>
{
    type Output = AffinePoint<C, N>;

    #[inline]
    fn mul(self, scalar: &T) -> Self::Output {
        self.scalar_mul(scalar.as_ref().as_bigint())
    }
}

impl<C: CurveConfig<N>, const N: usize, T: AsRef<UnverifiedFp<C::ScalarFieldConfig, N>>>
    MulAssign<&T> for AffinePoint<C, N>
{
    #[inline]
    fn mul_assign(&mut self, scalar: &T) {
        *self = self.scalar_mul(scalar.as_ref().as_bigint());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BigInt, R0VMFieldOps, field::Fp256};

    // --- Toy curve: y² = x³ + x + 1 over F_7, order 5 ---
    //
    // Points: O, (0,1), (2,5), (2,2), (0,6)
    // Group:  G=(0,1), 2G=(2,5), 3G=(2,2), 4G=(0,6), 5G=O

    enum FqConfig {}
    impl FieldConfig<8> for FqConfig {
        const MODULUS: BigInt<8> = BigInt::from_u32(7);
        type Ops = R0VMFieldOps;
    }
    type Fq = Fp256<FqConfig>;

    enum FrConfig {}
    impl FieldConfig<8> for FrConfig {
        const MODULUS: BigInt<8> = BigInt::from_u32(5);
        type Ops = R0VMFieldOps;
    }
    type Fr = Fp256<FrConfig>;

    enum Config {}
    impl CurveConfig<8> for Config {
        type BaseFieldConfig = FqConfig;
        type ScalarFieldConfig = FrConfig;
        type Ops = R0VMCurveOps;
        const COEFF_A: Fq = Fq::from_u32(1);
        const COEFF_B: Fq = Fq::from_u32(1);
        const GENERATOR: Affine = AffinePoint::from_xy(Fq::from_u32(0), Fq::from_u32(1));
        const COFACTOR: &'static [u32] = &[1];
    }
    type Affine = AffinePoint<Config, 8>;

    fn pt(x: u32, y: u32) -> Affine {
        AffinePoint::from_xy(Fq::from_u32(x), Fq::from_u32(y))
    }

    #[test]
    fn point_validation() {
        let g = Affine::GENERATOR;
        let o = Affine::IDENTITY;

        assert!(g.is_on_curve());
        assert!(o.is_on_curve());
        assert!(!g.is_identity());
        assert!(o.is_identity());

        // all curve points are accepted by new (on-curve check only)
        assert!(Affine::new(Fq::from_u32(0), Fq::from_u32(1)).is_some());
        assert!(Affine::new(Fq::from_u32(2), Fq::from_u32(5)).is_some());
        assert!(Affine::new(Fq::from_u32(2), Fq::from_u32(2)).is_some());
        assert!(Affine::new(Fq::from_u32(0), Fq::from_u32(6)).is_some());

        // off-curve point is rejected
        assert!(Affine::new(Fq::from_u32(1), Fq::from_u32(1)).is_none());

        // new_in_subgroup also validates (cofactor = 1, so same result)
        assert!(Affine::new_in_subgroup(Fq::from_u32(0), Fq::from_u32(1)).is_some());
        assert!(Affine::new_in_subgroup(Fq::from_u32(1), Fq::from_u32(1)).is_none());
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
        assert!((&two_g + &three_g).is_identity()); // 2G + 3G = 5G = O
    }

    #[test]
    fn scalar_mul() {
        let g = Affine::GENERATOR;

        assert_eq!(&g * &Fr::ONE, g);
        assert!((&g * &Fr::ZERO).is_identity());

        // [n]G = O (group order)
        let order = UnverifiedFp::from_bigint(Fr::MODULUS);
        assert!((&g * &order).is_identity());

        // [2]G + [3]G = [5]G = O
        let two = Fr::from_u32(2);
        let three = Fr::from_u32(3);
        assert!((&(&g * &two) + &(&g * &three)).is_identity());

        // [2]G matches known point
        assert_eq!(&g * &two, pt(2, 5));
    }

    #[test]
    fn clear_cofactor_is_noop_for_cofactor_1() {
        assert_eq!(Affine::GENERATOR.clear_cofactor(), Affine::GENERATOR);
        assert_eq!(Affine::IDENTITY.clear_cofactor(), Affine::IDENTITY);
        assert_eq!(pt(2, 5).clear_cofactor(), pt(2, 5));
    }
}

#[cfg(test)]
mod wycheproof {
    use super::*;
    use crate::BigInt;
    use ::wycheproof::{
        TestResult,
        ecdh::{TestName, TestSet},
    };

    /// Parses an uncompressed EC point (04 || x || y). Returns `None` for
    /// compressed, invalid, or wrong-length encodings.
    fn parse_point<C: CurveConfig<N>, const N: usize>(bytes: &[u8]) -> Option<AffinePoint<C, N>> {
        if bytes.first() != Some(&0x04) || bytes.len() != 1 + 2 * N * 4 {
            return None;
        }
        let x = Fp::from_bigint(BigInt::from_be_bytes(&bytes[1..1 + N * 4]))?;
        let y = Fp::from_bigint(BigInt::from_be_bytes(&bytes[1 + N * 4..]))?;
        AffinePoint::<C, N>::new(x, y)
    }

    /// Runs Wycheproof ECDH EcPoint tests as scalar multiplication tests.
    fn run_scalar_mul_tests<C: CurveConfig<N>, const N: usize>(name: TestName) {
        let test_set = TestSet::load(name).unwrap();

        for group in &test_set.test_groups {
            for tc in &group.tests {
                let result = (|| {
                    let point = parse_point::<C, N>(&tc.public_key)?;
                    if tc.private_key.len() > N * 4 {
                        return None;
                    }
                    let scalar = Fp::from_bigint(BigInt::from_be_bytes(&tc.private_key))?;
                    let (rx, _) = (&point * &scalar).xy()?;
                    Some(rx.to_bigint())
                })();

                let expected_x = BigInt::<N>::from_be_bytes(&tc.shared_secret);

                match (result, tc.result) {
                    (Some(rx), TestResult::Valid | TestResult::Acceptable) => {
                        assert_eq!(rx, expected_x, "tcId {}: {}", tc.tc_id, tc.comment);
                    }
                    (None, TestResult::Valid) => {
                        panic!("tcId {}: expected valid ({})", tc.tc_id, tc.comment);
                    }
                    (Some(_), TestResult::Invalid) => {
                        panic!("tcId {}: expected invalid ({})", tc.tc_id, tc.comment);
                    }
                    (None, TestResult::Invalid | TestResult::Acceptable) => {}
                }
            }
        }
    }

    #[test]
    fn secp256r1() {
        run_scalar_mul_tests::<crate::curves::secp256r1::Config, 8>(TestName::EcdhSecp256r1Ecpoint);
    }

    #[test]
    fn secp384r1() {
        run_scalar_mul_tests::<crate::curves::secp384r1::Config, 12>(
            TestName::EcdhSecp384r1Ecpoint,
        );
    }
}
