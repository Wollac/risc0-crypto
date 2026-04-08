mod ops;

pub use ops::R0VMCurveOps;

use crate::{
    BitAccess,
    field::{Field, FieldConfig, Fp, UnverifiedField, UnverifiedFp},
};
use core::{
    hash::{Hash, Hasher},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

/// The base field of curve `C` (used for point coordinates).
pub type BaseField<C, const N: usize> = <C as CurveConfig<N>>::BaseField;

/// The scalar field of curve `C` (used for scalar multiplication).
pub type ScalarField<C, const N: usize> = Fp<<C as CurveConfig<N>>::ScalarFieldConfig, N>;

/// Unverified base field element of curve `C` (used for intermediate coordinate arithmetic).
pub type UnverifiedBaseField<C, const N: usize> =
    <<C as CurveConfig<N>>::BaseField as Field>::Unverified;

/// An `[x, y]` coordinate pair as unverified base field elements. May not be in `[0, p)`.
pub type Coords<C, const N: usize> = [UnverifiedBaseField<C, N>; 2];

/// EC arithmetic operations for a short Weierstrass curve.
///
/// All methods are safe - unsafe FFI is contained within the backend implementation.
pub trait CurveOps<C: CurveConfig<N>, const N: usize>: Send + Sync + 'static {
    /// Computes `a + b` and writes the result into `out` (chord rule).
    ///
    /// Where `a = (x₁, y₁)`, `b = (x₂, y₂)`, and `out = (x₃, y₃)`:
    ///
    /// ```text
    /// λ  = (y₂ - y₁) / (x₂ - x₁)
    /// x₃ = λ² - x₁ - x₂
    /// y₃ = λ(x₁ - x₃) - y₁
    /// ```
    ///
    /// # Panics
    ///
    /// Panics when `x₁ == x₂ mod p` - the chord formula divides by zero. Handle same-x cases
    /// (doubling, inverse) before calling.
    fn add_into(a: &Coords<C, N>, b: &Coords<C, N>, out: &mut Coords<C, N>);

    /// Computes `[2]a` and writes the result into `out` (tangent rule).
    ///
    /// Where `a = (x, y)` and `out = (x₂, y₂)`:
    ///
    /// ```text
    /// λ  = (3x² + a) / (2y)
    /// x₂ = λ² - 2x
    /// y₂ = λ(x - x₂) - y
    /// ```
    ///
    /// # Panics
    ///
    /// Panics when `y == 0 mod p` - the tangent formula divides by `2y`.
    fn double_into(a: &Coords<C, N>, out: &mut Coords<C, N>);

    /// By-value version of [`add_into`](Self::add_into). Same panic conditions apply.
    #[inline]
    fn add(a: &Coords<C, N>, b: &Coords<C, N>) -> Coords<C, N> {
        let mut out = *a;
        Self::add_into(a, b, &mut out);
        out
    }

    /// By-value version of [`double_into`](Self::double_into). Same panic conditions apply.
    #[inline]
    fn double(a: &Coords<C, N>) -> Coords<C, N> {
        let mut out = *a;
        Self::double_into(a, &mut out);
        out
    }
}

/// EC arithmetic for a short Weierstrass curve `y² = x³ + ax + b`.
///
/// Implement this trait to define a new curve. EC operations are delegated to the associated
/// [`Ops`](Self::Ops) type, which implements [`CurveOps`]. The base field can be any type
/// implementing [`Field`] (e.g. `Fp` for G1 curves, `Fp2` for G2 curves).
pub trait CurveConfig<const N: usize>: Sized + Send + Sync + 'static {
    /// Base field type (coordinates). Use [`Fp`] for prime-field curves.
    type BaseField: Field;
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
        let order = UnverifiedFp::<Self::ScalarFieldConfig, N>::from_bigint(
            Self::ScalarFieldConfig::MODULUS,
        );
        (p * &order).is_identity()
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
    /// Coordinate buffer. Always present; contents are meaningless when `identity` is true.
    /// Coordinates are canonical (`< p`) after construction; arithmetic operations may produce
    /// non-canonical results. Access via `xy()` / `xy_ref()` (check - asserts canonical) or
    /// `xy_unverified()` (defers to caller).
    coords: Coords<C, N>,
    /// `true` for the point at infinity. When set, `coords` is a scratch buffer - do not read.
    identity: bool,
}

// --- Constants and constructors ---

impl<C: CurveConfig<N>, const N: usize> AffinePoint<C, N> {
    /// The point at infinity (additive identity).
    pub const IDENTITY: Self = Self {
        coords: [
            <<C::BaseField as Field>::Unverified as UnverifiedField>::ZERO,
            <<C::BaseField as Field>::Unverified as UnverifiedField>::ZERO,
        ],
        identity: true,
    };

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
    pub unsafe fn new_unchecked(x: BaseField<C, N>, y: BaseField<C, N>) -> Self {
        Self::from_xy(x, y)
    }

    /// Non-const constructor from verified coordinates.
    #[inline]
    pub(crate) fn from_xy(x: BaseField<C, N>, y: BaseField<C, N>) -> Self {
        Self { coords: [x.into_unverified(), y.into_unverified()], identity: false }
    }

    /// Const-compatible constructor from raw unverified coordinates. The crate upholds the
    /// on-curve invariant via hardcoded generator coordinates (validated by tests) and
    /// arithmetic operations that preserve on-curve by construction.
    #[inline]
    pub(crate) const fn from_raw_coords(coords: Coords<C, N>) -> Self {
        Self { coords, identity: false }
    }

    /// Returns `true` if this is the point at infinity.
    #[inline]
    pub const fn is_identity(&self) -> bool {
        self.identity
    }

    /// Returns the `(x, y)` coordinates as verified field elements, or `None` for the identity.
    ///
    /// Panics if either coordinate is not in `[0, p)`.
    #[inline(always)]
    pub fn xy(&self) -> Option<(BaseField<C, N>, BaseField<C, N>)> {
        if self.identity { None } else { Some((self.coords[0].check(), self.coords[1].check())) }
    }

    /// Returns the `(x, y)` coordinates as verified field element references, or `None` for
    /// the identity. Zero-cost - no copy, just a pointer cast.
    ///
    /// Panics if either coordinate is not in `[0, p)`.
    #[inline(always)]
    pub fn xy_ref(&self) -> Option<(&BaseField<C, N>, &BaseField<C, N>)> {
        if self.identity {
            None
        } else {
            Some((self.coords[0].check_ref(), self.coords[1].check_ref()))
        }
    }

    /// Returns the `(x, y)` coordinates as unverified field element references, or `None` for
    /// the identity.
    ///
    /// Use this for intermediate arithmetic where canonicality checks can be deferred.
    #[inline(always)]
    pub const fn xy_unverified(
        &self,
    ) -> Option<(&UnverifiedBaseField<C, N>, &UnverifiedBaseField<C, N>)> {
        if self.identity { None } else { Some((&self.coords[0], &self.coords[1])) }
    }

    /// Checks whether `(x, y)` satisfies the curve equation `y² = x³ + ax + b`.
    #[must_use]
    pub fn is_on_curve(&self) -> bool {
        let Some((x, y)) = self.xy_unverified() else {
            return true; // identity is on every curve
        };

        y.mul(y).check_is_eq(&Self::curve_rhs(x))
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

    /// Raw integer check for y == 0 (2-torsion). Not field equality - only catches the
    /// canonical zero. y == 0 is impossible for on-curve points when the cofactor is odd (no
    /// 2-torsion), so this check is skipped at compile time for odd-cofactor curves.
    #[inline(always)]
    fn raw_is_y_zero(&self) -> bool {
        !cofactor::is_odd::<C, _>() && self.coords[1].raw_is_zero()
    }

    /// Adds [`COEFF_A`](CurveConfig::COEFF_A) in place, skipped at compile time when `a == 0`.
    #[inline(always)]
    fn add_a(val: &mut UnverifiedBaseField<C, N>) {
        if !C::COEFF_A.is_zero() {
            val.add_assign(C::COEFF_A.as_unverified());
        }
    }

    /// Computes the curve RHS `x³ + ax + b` for a given x-coordinate.
    fn curve_rhs(x: &UnverifiedBaseField<C, N>) -> UnverifiedBaseField<C, N> {
        let mut rhs = x.mul(x);
        Self::add_a(&mut rhs);
        rhs.mul_assign(x);
        rhs.add_assign(C::COEFF_B.as_unverified());
        rhs
    }

    /// Computes `[2]src` and writes the result into `self`.
    #[inline]
    pub fn double_into(&mut self, src: &Self) {
        // raw_is_y_zero handles the honest case; a dishonest non-canonical zero
        // (y > 0 but y == 0 mod p) needs no check since double_into panics on y == 0 mod p anyway
        if src.identity || src.raw_is_y_zero() {
            self.identity = true;
            return;
        }

        C::Ops::double_into(&src.coords, &mut self.coords);
        self.identity = false;
    }

    /// Returns `[2]self`.
    #[inline]
    pub fn double(&self) -> Self {
        // raw_is_y_zero is sound; see double_into for rationale
        if self.identity || self.raw_is_y_zero() {
            return Self::IDENTITY;
        }

        Self { coords: C::Ops::double(&self.coords), identity: false }
    }

    /// Computes `a + b` and writes the result into `self`.
    #[inline]
    pub fn add_into(&mut self, a: &Self, b: &Self) {
        match (a.identity, b.identity) {
            (_, true) => *self = *a,
            (true, _) => *self = *b,
            // raw_eq handles the honest case; a dishonest non-canonical equality needs no check
            // since add_into panics on x₁ == x₂ mod p anyway
            _ if a.coords[0].raw_eq(&b.coords[0]) => {
                if a.coords[1].check_is_eq(&b.coords[1]) {
                    self.double_into(a);
                } else {
                    self.identity = true;
                }
            }
            _ => {
                C::Ops::add_into(&a.coords, &b.coords, &mut self.coords);
                self.identity = false;
            }
        }
    }

    /// Returns `self + rhs`. By-value counterpart of [`add_into`](Self::add_into).
    ///
    /// Duplicates the match logic from `add_into` rather than delegating - the extra copy
    /// through `add_into`'s `&mut self` output parameter measurably hurts R0VM performance
    /// (~50%).
    #[inline(always)]
    fn add(&self, rhs: &Self) -> Self {
        match (self.identity, rhs.identity) {
            (_, true) => *self,
            (true, _) => *rhs,
            // raw_eq is sound; see add_into for rationale
            _ if self.coords[0].raw_eq(&rhs.coords[0]) => {
                if self.coords[1].check_is_eq(&rhs.coords[1]) {
                    self.double()
                } else {
                    Self::IDENTITY
                }
            }
            _ => Self { coords: C::Ops::add(&self.coords, &rhs.coords), identity: false },
        }
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
        if self.identity || n == 0 {
            return Self::IDENTITY;
        }

        // double-buffered: swap references (pointer-sized) instead of values
        let mut t1 = *self;
        let mut t2 = Self::IDENTITY;
        let mut cur = &mut t1;
        let mut next = &mut t2;

        // bit n-1 is always 1 (n = bits()), so start from n-2
        for i in (0..n - 1).rev() {
            next.double_into(cur);
            if scalar.bit(i) {
                cur.add_into(next, self);
            } else {
                core::mem::swap(&mut cur, &mut next);
            }
        }

        *cur
    }

    /// Computes `[a]P + [b]Q` via Shamir's trick (interleaved double-and-add).
    ///
    /// Saves ~n doublings compared to two independent scalar multiplications. Both scalars are
    /// interpreted as unsigned integers and may be `>= n` (the group order).
    #[inline]
    pub fn double_scalar_mul(
        a: &ScalarField<C, N>,
        p: &Self,
        b: &ScalarField<C, N>,
        q: &Self,
    ) -> Self {
        Self::double_scalar_mul_inner(a.as_bigint(), p, b.as_bigint(), q)
    }

    /// Inner implementation using [`BitAccess`] scalars.
    fn double_scalar_mul_inner(
        a: &(impl BitAccess + ?Sized),
        p: &Self,
        b: &(impl BitAccess + ?Sized),
        q: &Self,
    ) -> Self {
        let n = a.bits().max(b.bits());

        // precompute P + Q for the (1, 1) bit-pair case
        let pq = p.add(q);

        let mut t1 = Self::IDENTITY;
        let mut t2 = Self::IDENTITY;
        let mut cur = &mut t1;
        let mut next = &mut t2;

        for i in (0..n).rev() {
            next.double_into(cur);
            match (a.bit(i), b.bit(i)) {
                (true, true) => cur.add_into(next, &pq),
                (true, false) => cur.add_into(next, p),
                (false, true) => cur.add_into(next, q),
                (false, false) => core::mem::swap(&mut cur, &mut next),
            }
        }

        *cur
    }
}

// --- Prime-field-specific methods (point decompression) ---
//
// These require the base field to be a concrete prime field `Fp<P, N>`, not a generic `Field`.
// Extension field curves (e.g. G2 over Fp2) don't support decompression.

impl<P: FieldConfig<N>, C: CurveConfig<N, BaseField = Fp<P, N>>, const N: usize> AffinePoint<C, N> {
    /// Returns the two y-coordinates on the curve for the given `x`, or `None` if no point
    /// with that x-coordinate exists. Returns `(y_even, y_odd)`.
    ///
    /// The corresponding points are on the curve but not necessarily in the prime-order
    /// subgroup.
    pub fn ys_from_x(x: impl AsRef<UnverifiedFp<P, N>>) -> Option<(Fp<P, N>, Fp<P, N>)> {
        // y² = x³ + ax + b
        let x = x.as_ref();
        let y = Self::curve_rhs(x).sqrt()?.check();
        let neg_y = -&y;
        if y.as_bigint().is_even() { Some((y, neg_y)) } else { Some((neg_y, y)) }
    }

    /// Decompresses a point from its x-coordinate and y-parity bit, or `None` if no point
    /// with that x-coordinate exists.
    ///
    /// The returned point is on the curve but not necessarily in the prime-order subgroup.
    pub fn decompress(x: Fp<P, N>, is_y_odd: bool) -> Option<Self> {
        let (y_even, y_odd) = Self::ys_from_x(x)?;
        Some(Self::from_xy(x, if is_y_odd { y_odd } else { y_even }))
    }
}

// --- Std trait impls ---

impl<C: CurveConfig<N>, const N: usize> core::fmt::Debug for AffinePoint<C, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.xy_unverified() {
            None => write!(f, "AffinePoint(Identity)"),
            Some((x, y)) => f.debug_struct("AffinePoint").field("x", x).field("y", y).finish(),
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
        if !result.identity {
            result.coords[1].neg_in_place();
        }
        result
    }
}

impl<C: CurveConfig<N>, const N: usize> Add for &AffinePoint<C, N> {
    type Output = AffinePoint<C, N>;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        AffinePoint::add(self, rhs)
    }
}

impl<C: CurveConfig<N>, const N: usize> AddAssign<&Self> for AffinePoint<C, N> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        *self = &*self + rhs;
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
        *self = &*self - rhs;
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
        type BaseField = Fq;
        type ScalarFieldConfig = FrConfig;
        type Ops = R0VMCurveOps;
        const COEFF_A: Fq = Fq::from_u32(1);
        const COEFF_B: Fq = Fq::from_u32(1);
        const GENERATOR: Affine = AffinePoint::from_raw_coords([
            UnverifiedFp::from_bigint(BigInt::from_u32(0)),
            UnverifiedFp::from_bigint(BigInt::from_u32(1)),
        ]);
        const COFACTOR: &'static [u32] = &[1];
    }
    type Affine = AffinePoint<Config, 8>;

    const fn pt(x: u32, y: u32) -> Affine {
        AffinePoint::from_raw_coords([
            UnverifiedFp::from_bigint(BigInt::from_u32(x)),
            UnverifiedFp::from_bigint(BigInt::from_u32(y)),
        ])
    }

    const GROUP: [Affine; 5] = [Affine::IDENTITY, Affine::GENERATOR, pt(2, 5), pt(2, 2), pt(0, 6)];

    #[test]
    fn point_validation() {
        let (o, g) = (&GROUP[0], &GROUP[1]);

        assert!(g.is_on_curve());
        assert!(o.is_on_curve());
        assert!(!g.is_identity());
        assert!(o.is_identity());

        // all non-identity group elements are accepted by new (on-curve check)
        for p in &GROUP[1..] {
            let (x, y) = p.xy().unwrap();
            assert!(Affine::new(x, y).is_some());
        }

        // off-curve point is rejected
        assert!(Affine::new(Fq::from_u32(1), Fq::from_u32(1)).is_none());

        // new_in_subgroup also validates (cofactor = 1, so same result)
        assert!(Affine::new_in_subgroup(Fq::from_u32(0), Fq::from_u32(1)).is_some());
        assert!(Affine::new_in_subgroup(Fq::from_u32(1), Fq::from_u32(1)).is_none());
    }

    #[test]
    fn point_addition() {
        let (o, g) = (&GROUP[0], &GROUP[1]);

        // identity
        assert_eq!(g + o, *g);
        assert_eq!(o + g, *g);
        assert_eq!(g - o, *g);
        assert!((g - g).is_identity());

        // doubling
        let two_g = g.double();
        assert_eq!(g + g, two_g);

        // commutativity
        assert_eq!(g + &two_g, &two_g + g);

        // negation
        assert!((-o).is_identity());
        assert_eq!(-g, GROUP[4]); // -G = 4G (order 5)
        assert_eq!(&(-g) + g, *o); // -G + G = O

        // subtraction: 3G - 2G = G
        assert_eq!(&GROUP[3] - &two_g, *g);

        // walk the full group: G, 2G, 3G, 4G, 5G=O
        assert_eq!(two_g, GROUP[2]);
        assert_eq!(g + &two_g, GROUP[3]);
        assert_eq!(&two_g + &two_g, GROUP[4]);
        assert!((&two_g + &GROUP[3]).is_identity());
    }

    #[test]
    fn scalar_mul() {
        let n = GROUP.len() as u32; // group order

        // exhaustive: [k]P for all points P and scalars k in 0..n
        for (i, p) in GROUP.iter().enumerate() {
            for k in 0..n {
                let expected = GROUP[((i as u32 * k) % n) as usize];
                assert_eq!(p * &Fr::from_u32(k), expected, "failed for [{k}]GROUP[{i}]");
            }
        }
    }

    #[test]
    fn double_scalar_mul() {
        let n = GROUP.len() as u32; // group order
        let (g, two_g) = (&GROUP[1], &GROUP[2]);

        // exhaustive: [a]G + [b](2G) for all (a, b) in {0..n}²
        for a in 0..n {
            for b in 0..n {
                let res = Affine::double_scalar_mul(&Fr::from_u32(a), g, &Fr::from_u32(b), two_g);
                let expected = GROUP[((a + 2 * b) % n) as usize];
                assert_eq!(res, expected, "failed for a={a}, b={b}");
            }
        }
    }

    #[test]
    fn ys_from_x() {
        let fq = Fq::from_u32;

        // x = 0: y² = 1, roots are 1 (odd) and 6 (even) -> (even, odd) = (6, 1)
        let (y_even, y_odd) = Affine::ys_from_x(fq(0)).unwrap();
        assert!(y_even.as_bigint().is_even());
        assert!(y_odd.as_bigint().is_odd());
        assert_eq!((y_even, y_odd), (fq(6), fq(1)));

        // x = 2: roots are 2 (even) and 5 (odd)
        let (y_even, y_odd) = Affine::ys_from_x(fq(2)).unwrap();
        assert!(y_even.as_bigint().is_even());
        assert!(y_odd.as_bigint().is_odd());
        assert_eq!(&y_even * &y_even, &y_odd * &y_odd);

        // no curve point at x = 1
        assert!(Affine::ys_from_x(fq(1)).is_none());

        // decompress roundtrip
        assert_eq!(Affine::decompress(fq(0), false), Some(pt(0, 6)));
        assert_eq!(Affine::decompress(fq(0), true), Some(pt(0, 1)));
        assert!(Affine::decompress(fq(1), false).is_none());
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

    /// Parses a SEC1-encoded EC point (uncompressed or compressed). Returns `None` for invalid
    /// encodings, off-curve points, or points not in the prime-order subgroup.
    fn parse_point<P: FieldConfig<N>, C: CurveConfig<N, BaseField = Fp<P, N>>, const N: usize>(
        bytes: &[u8],
    ) -> Option<AffinePoint<C, N>> {
        let prefix = *bytes.first()?;
        let coord_len = N * 4;
        match prefix {
            0x04 if bytes.len() == 1 + 2 * coord_len => {
                let x = Fp::from_bigint(BigInt::from_be_bytes(&bytes[1..1 + coord_len]))?;
                let y = Fp::from_bigint(BigInt::from_be_bytes(&bytes[1 + coord_len..]))?;
                AffinePoint::<C, N>::new_in_subgroup(x, y)
            }
            0x02 | 0x03 if bytes.len() == 1 + coord_len => {
                let x = Fp::from_bigint(BigInt::from_be_bytes(&bytes[1..]))?;
                let is_y_odd = prefix == 0x03;
                let pt = AffinePoint::<C, N>::decompress(x, is_y_odd)?;
                pt.is_in_correct_subgroup().then_some(pt)
            }
            _ => None,
        }
    }

    /// Runs Wycheproof ECDH EcPoint tests as scalar multiplication tests.
    fn run_scalar_mul_tests<
        P: FieldConfig<N>,
        C: CurveConfig<N, BaseField = Fp<P, N>>,
        const N: usize,
    >(
        name: TestName,
    ) {
        let test_set = TestSet::load(name).unwrap();

        for group in &test_set.test_groups {
            for tc in &group.tests {
                let result = (|| {
                    let point = parse_point::<P, C, N>(&tc.public_key)?;
                    let key_start = tc.private_key.iter().position(|&b| b != 0).unwrap_or(0);
                    let key = &tc.private_key[key_start..];
                    if key.len() > N * 4 {
                        return None;
                    }
                    let scalar = Fp::from_bigint(BigInt::from_be_bytes(key))?;
                    let (rx, _) = (&point * &scalar).xy()?;
                    Some(rx.to_bigint())
                })();

                if tc.result.must_fail() {
                    assert!(
                        result.is_none(),
                        "tcId {}: expected invalid ({})",
                        tc.tc_id,
                        tc.comment
                    );
                } else if let Some(rx) = result {
                    let expected_x = BigInt::<N>::from_be_bytes(&tc.shared_secret);
                    assert_eq!(rx, expected_x, "tcId {}: {}", tc.tc_id, tc.comment);
                } else if tc.result == TestResult::Valid {
                    panic!("tcId {}: expected valid ({})", tc.tc_id, tc.comment);
                }
            }
        }
    }

    #[test]
    fn secp256r1() {
        run_scalar_mul_tests::<
            crate::curves::secp256r1::FqConfig,
            crate::curves::secp256r1::Config,
            8,
        >(TestName::EcdhSecp256r1Ecpoint);
    }

    #[test]
    fn secp384r1() {
        run_scalar_mul_tests::<
            crate::curves::secp384r1::FqConfig,
            crate::curves::secp384r1::Config,
            12,
        >(TestName::EcdhSecp384r1Ecpoint);
    }
}
