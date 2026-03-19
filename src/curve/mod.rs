pub(crate) mod ops;

use crate::{
    BigInt, BitAccess, R0FieldConfig,
    field::{Fp, FpConfig, Unreduced},
};
use bytemuck::TransparentWrapper;
use core::{
    marker::PhantomData,
    mem::MaybeUninit,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    ptr,
};

/// The base field of curve `C` (used for point coordinates).
pub type BaseField<C, const N: usize> = Fp<<C as SWCurveConfig<N>>::BaseFieldConfig, N>;

/// The scalar field of curve `C` (used for scalar multiplication).
pub type ScalarField<C, const N: usize> = Fp<<C as SWCurveConfig<N>>::ScalarFieldConfig, N>;

/// Unreduced base field element of curve `C` (used for intermediate coordinate arithmetic).
type UnreducedBaseField<C, const N: usize> = Unreduced<<C as SWCurveConfig<N>>::BaseFieldConfig, N>;

/// Raw `[x, y]` coordinate pair. May not be reduced to `[0, p)`.
type RawCoords<const N: usize> = [BigInt<N>; 2];

/// Defines a short Weierstrass curve for the R0VM backend. Implement this trait to introduce a
/// new curve; [`SWCurveConfig`] is provided automatically via a blanket impl.
pub trait R0CurveConfig<const N: usize>: Send + Sync + 'static + Sized {
    type BaseFieldConfig: R0FieldConfig<N>;
    type ScalarFieldConfig: R0FieldConfig<N>;

    const COEFF_A: Fp<Self::BaseFieldConfig, N>;
    const COEFF_B: Fp<Self::BaseFieldConfig, N>;
    const GENERATOR: AffinePoint<Self, N>;

    /// Curve parameters `[modulus, a, b]` for the R0VM EC circuits.
    const CURVE_PARAMS: [BigInt<N>; 3] =
        [Self::BaseFieldConfig::MODULUS, Self::COEFF_A.to_bigint(), Self::COEFF_B.to_bigint()];

    /// Subgroup membership check. Default checks `[order]P == O`.
    /// Override for curves with cofactor 1 (where this is always true).
    fn is_in_correct_subgroup(p: &AffinePoint<Self, N>) -> bool
    where
        Self: SWCurveConfig<N>,
    {
        subgroup_check_by_order(p)
    }
}

/// EC arithmetic for a short Weierstrass curve `y² = x³ + ax + b`.
///
/// Provided automatically via a blanket impl over [`R0CurveConfig`]. Implement directly (instead
/// of [`R0CurveConfig`]) to use a different backend for `ec_add`/`ec_double`.
///
/// # Safety
///
/// The `ec_*` methods have the following contract:
/// * `out` must point to writeable, aligned memory for `[BigInt<N>; 2]`.
/// * `out` need not be initialized - the implementation writes all coordinates.
/// * `out` may alias the first operand - the implementation reads all inputs before writing.
/// * Results need not be reduced to `[0, p)`.
pub trait SWCurveConfig<const N: usize>: Send + Sync + 'static + Sized {
    type BaseFieldConfig: FpConfig<N>;
    type ScalarFieldConfig: FpConfig<N>;

    const COEFF_A: BaseField<Self, N>;
    const COEFF_B: BaseField<Self, N>;
    const GENERATOR: AffinePoint<Self, N>;

    /// Subgroup membership check. Default checks `[order]P == O`.
    /// Override for curves with cofactor 1 (where this is always true).
    fn is_in_correct_subgroup(p: &AffinePoint<Self, N>) -> bool {
        subgroup_check_by_order(p)
    }

    /// Computes `out = a + b` on the curve (chord rule).
    ///
    /// # Preconditions
    ///
    /// The caller must ensure `x₁ != x₂`. When `x₁ == x₂` the chord formula divides by zero.
    /// Handle same-x cases (doubling, inverse) before calling.
    ///
    /// # Safety
    /// See [trait-level docs](Self).
    unsafe fn ec_add(a: *const RawCoords<N>, b: &RawCoords<N>, out: *mut RawCoords<N>);

    /// Computes `out = [2]a` on the curve (tangent rule).
    ///
    /// # Preconditions
    ///
    /// The caller must ensure `y != 0`. When `y == 0` the tangent formula divides by `2y`.
    ///
    /// # Safety
    /// See [trait-level docs](Self).
    unsafe fn ec_double(a: *const RawCoords<N>, out: *mut RawCoords<N>);
}

/// Checks `[order]P == O`. Used as the default subgroup check for curves with a cofactor.
fn subgroup_check_by_order<C: SWCurveConfig<N>, const N: usize>(p: &AffinePoint<C, N>) -> bool {
    (p * Unreduced::wrap_ref(&C::ScalarFieldConfig::MODULUS)).is_identity()
}

/// A point on a short Weierstrass curve in affine coordinates `(x, y)`.
///
/// Internally, coordinates may not be in canonical form `[0, p)` after arithmetic operations.
/// Access them via [`xy`](Self::xy) (validates via [`Unreduced::check`]) or
/// [`xy_unreduced`](Self::xy_unreduced) for intermediate arithmetic.
///
/// `None` represents the point at infinity (identity). Supports addition, negation, subtraction,
/// doubling, and scalar multiplication via operator overloads (`+`, `-`, `*`).
#[derive(educe::Educe)]
#[educe(Copy, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub struct AffinePoint<C, const N: usize> {
    coords: Option<RawCoords<N>>,
    _marker: PhantomData<C>,
}

impl<C, const N: usize> core::fmt::Debug for AffinePoint<C, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.coords {
            Some(coords) => {
                f.debug_struct("AffinePoint").field("x", &coords[0]).field("y", &coords[1]).finish()
            }
            None => write!(f, "AffinePoint(Identity)"),
        }
    }
}

// --- Typed accessors and validation (requires SWCurveConfig) ---

impl<C: SWCurveConfig<N>, const N: usize> AffinePoint<C, N> {
    /// The point at infinity (additive identity).
    pub const IDENTITY: Self = Self { coords: None, _marker: PhantomData };

    /// The curve's standard generator point.
    pub const GENERATOR: Self = C::GENERATOR;

    /// Creates a point from coordinates, returning `None` if the point is not on the curve.
    ///
    /// Does not check subgroup membership - use [`new_in_subgroup`](Self::new_in_subgroup) for
    /// that. For curves with cofactor 1, `new` and `new_in_subgroup` are equivalent.
    #[inline]
    pub fn new(x: BaseField<C, N>, y: BaseField<C, N>) -> Option<Self> {
        let p = Self::from_xy(x, y);
        if p.is_on_curve() { Some(p) } else { None }
    }

    /// Creates a point from coordinates, returning `None` if the point is not on the curve or
    /// not in the correct subgroup.
    #[inline]
    pub fn new_in_subgroup(x: BaseField<C, N>, y: BaseField<C, N>) -> Option<Self> {
        let p = Self::new(x, y)?;
        if p.is_in_correct_subgroup() { Some(p) } else { None }
    }

    /// Creates a point from coordinates without validating on-curve or subgroup membership.
    ///
    /// # Safety
    ///
    /// The caller must ensure the point `(x, y)` satisfies the curve equation `y² = x³ + ax + b`.
    /// Passing an off-curve point to arithmetic operations is undefined behavior at the R0VM
    /// circuit level.
    #[inline]
    pub const unsafe fn new_unchecked(x: BaseField<C, N>, y: BaseField<C, N>) -> Self {
        Self::from_xy(x, y)
    }

    /// Internal unchecked constructor. The crate upholds the on-curve invariant via:
    /// - hardcoded generator coordinates (validated by tests)
    /// - arithmetic operations that preserve on-curve by construction
    #[inline]
    pub(crate) const fn from_xy(x: BaseField<C, N>, y: BaseField<C, N>) -> Self {
        Self { coords: Some([x.to_bigint(), y.to_bigint()]), _marker: PhantomData }
    }

    /// Returns `true` if this is the point at infinity.
    #[inline]
    pub const fn is_identity(&self) -> bool {
        self.coords.is_none()
    }

    /// Returns the `(x, y)` coordinates as checked [`Fp`] values, or `None` for the identity.
    ///
    /// Panics if either coordinate is not in `[0, p)`.
    #[inline]
    pub const fn xy(&self) -> Option<(BaseField<C, N>, BaseField<C, N>)> {
        match self.coords {
            None => None,
            Some(ref coords) => Some((
                Unreduced::from_bigint(coords[0]).check(),
                Unreduced::from_bigint(coords[1]).check(),
            )),
        }
    }

    /// Returns the `(x, y)` coordinates as [`Unreduced`] references, or `None` for the identity.
    ///
    /// Use this for intermediate arithmetic where canonicality checks can be deferred.
    #[inline]
    pub fn xy_unreduced(&self) -> Option<(&UnreducedBaseField<C, N>, &UnreducedBaseField<C, N>)> {
        match self.coords {
            None => None,
            Some(ref coords) => {
                Some((Unreduced::wrap_ref(&coords[0]), Unreduced::wrap_ref(&coords[1])))
            }
        }
    }

    /// Checks `y² = x³ + ax + b` using field arithmetic.
    #[must_use]
    pub fn is_on_curve(&self) -> bool {
        let Some((x, y)) = self.xy_unreduced() else {
            return true; // identity is on every curve
        };

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

// --- Arithmetic ---

impl<C: SWCurveConfig<N>, const N: usize> AffinePoint<C, N> {
    /// Computes `[2]self`.
    #[inline]
    pub fn double(&self) -> Self {
        let Some(a_xy) = &self.coords else {
            return Self::IDENTITY;
        };
        if a_xy[1].is_zero() {
            return Self::IDENTITY;
        }

        // SAFETY: out is fully written by ec_double before assume_init.
        unsafe {
            let mut out = MaybeUninit::uninit();
            C::ec_double(a_xy, out.as_mut_ptr());
            Self { coords: Some(out.assume_init()), _marker: PhantomData }
        }
    }

    /// Computes `[2]self` in place.
    #[inline]
    pub fn double_assign(&mut self) {
        let Some(a_xy) = &mut self.coords else {
            return;
        };
        if a_xy[1].is_zero() {
            self.coords = None;
            return;
        }
        let ptr = ptr::from_mut(a_xy);
        // SAFETY: a (ptr) aliases out (ptr) per SWCurveConfig's contract.
        unsafe { C::ec_double(ptr, ptr) };
    }

    /// Computes `[scalar]self` via MSB-first double-and-add.
    ///
    /// Works for any point on the curve regardless of subgroup. The scalar is interpreted as an
    /// unsigned integer and may be `>= n` (the group order). Behavior is undefined for points
    /// not on the curve.
    fn scalar_mul(&self, scalar: &BigInt<N>) -> Self {
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

// --- Operator impls ---
//
// - &ref Op &ref: new output via MaybeUninit
// - val OpAssign &ref: in-place via aliased pointer

impl<C: SWCurveConfig<N>, const N: usize> Add for &AffinePoint<C, N> {
    type Output = AffinePoint<C, N>;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        match (&self.coords, &rhs.coords) {
            (_, None) => *self,
            (None, _) => *rhs,
            // same x: either doubling (P + P) or cancellation (P + (-P))
            (Some(a_xy), Some(b_xy)) if a_xy[0] == b_xy[0] => {
                if a_xy[1] == b_xy[1] {
                    self.double()
                } else {
                    AffinePoint::IDENTITY
                }
            }
            (Some(a_xy), Some(b_xy)) => {
                // SAFETY: out is fully written by ec_add before assume_init.
                unsafe {
                    let mut out = MaybeUninit::uninit();
                    C::ec_add(a_xy, b_xy, out.as_mut_ptr());
                    AffinePoint { coords: Some(out.assume_init()), _marker: PhantomData }
                }
            }
        }
    }
}

impl<C: SWCurveConfig<N>, const N: usize> Sub for &AffinePoint<C, N> {
    type Output = AffinePoint<C, N>;

    #[inline]
    fn sub(self, rhs: Self) -> AffinePoint<C, N> {
        self + &(-rhs)
    }
}

impl<C: SWCurveConfig<N>, const N: usize, T: AsRef<Unreduced<C::ScalarFieldConfig, N>>> Mul<&T>
    for &AffinePoint<C, N>
{
    type Output = AffinePoint<C, N>;

    #[inline]
    fn mul(self, scalar: &T) -> Self::Output {
        self.scalar_mul(scalar.as_ref().as_bigint())
    }
}

impl<C: SWCurveConfig<N>, const N: usize> Neg for &AffinePoint<C, N> {
    type Output = AffinePoint<C, N>;

    #[inline]
    fn neg(self) -> AffinePoint<C, N> {
        let mut result = *self;
        if let Some(a_xy) = &mut result.coords {
            Unreduced::<C::BaseFieldConfig, N>::wrap_mut(&mut a_xy[1]).neg_in_place();
        }
        result
    }
}

impl<C: SWCurveConfig<N>, const N: usize> AddAssign<&Self> for AffinePoint<C, N> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        match (&mut self.coords, &rhs.coords) {
            (_, None) => {}
            (None, Some(_)) => *self = *rhs,
            // same x: either doubling (P + P) or cancellation (P + (-P))
            (Some(a_xy), Some(b_xy)) if a_xy[0] == b_xy[0] => {
                if a_xy[1] == b_xy[1] {
                    self.double_assign();
                } else {
                    self.coords = None;
                }
            }
            (Some(a_xy), Some(b_xy)) => {
                let ptr = ptr::from_mut(a_xy);
                // SAFETY: a_xy (ptr) aliases out (ptr) per SWCurveConfig's contract.
                unsafe { C::ec_add(ptr, b_xy, ptr) };
            }
        }
    }
}

impl<C: SWCurveConfig<N>, const N: usize> SubAssign<&Self> for AffinePoint<C, N> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        self.add_assign(&(-rhs));
    }
}

impl<C: SWCurveConfig<N>, const N: usize, T: AsRef<Unreduced<C::ScalarFieldConfig, N>>>
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
    impl R0CurveConfig<8> for Config {
        type BaseFieldConfig = FqConfig;
        type ScalarFieldConfig = FrConfig;
        const COEFF_A: Fq = Fq::from_u32(1);
        const COEFF_B: Fq = Fq::from_u32(1);
        const GENERATOR: Affine = AffinePoint::from_xy(Fq::from_u32(0), Fq::from_u32(1));
        fn is_in_correct_subgroup(_: &AffinePoint<Self, 8>) -> bool {
            true // cofactor = 1
        }
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
