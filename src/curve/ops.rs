use super::{AffinePoint, SWCurveConfig, ffi};
use crate::{BigInt, BitAccess, Unreduced};
use core::{
    marker::PhantomData,
    mem::MaybeUninit,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

impl<C: SWCurveConfig<N>, const N: usize> AffinePoint<C, N> {
    /// Returns `[2]P` (point doubling).
    #[inline]
    pub fn double(&self) -> Self {
        let Some(a_xy) = &self.coords else {
            return Self::IDENTITY;
        };
        // y == 0 means order-2 point: 2P = O (double circuit would divide by zero)
        if a_xy[1].is_zero() {
            return Self::IDENTITY;
        }

        unsafe {
            let mut out = MaybeUninit::uninit();
            ffi::ec_double_raw(a_xy, &Self::CURVE_PARAMS, out.as_mut_ptr());
            Self { coords: Some(out.assume_init()), _marker: PhantomData }
        }
    }

    /// Computes `[2]P` in-place.
    #[inline]
    pub fn double_assign(&mut self) {
        let Some(a_xy) = &mut self.coords else {
            return;
        };
        // y == 0 means order-2 point: 2P = O (double circuit would divide by zero)
        if a_xy[1].is_zero() {
            self.coords = None;
            return;
        }
        let ptr = core::ptr::from_mut(a_xy);
        unsafe { ffi::ec_double_raw(ptr, &Self::CURVE_PARAMS, ptr) };
    }
}

impl<C: SWCurveConfig<N>, const N: usize> Add for &AffinePoint<C, N> {
    type Output = AffinePoint<C, N>;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        let (Some(a), Some(b)) = (&self.coords, &rhs.coords) else {
            return if self.coords.is_some() { *self } else { *rhs };
        };
        if a[0] == b[0] {
            if a[1] != b[1] || a[1].is_zero() {
                return AffinePoint::IDENTITY;
            }
            return self.double();
        }

        unsafe {
            let mut out = MaybeUninit::uninit();
            ffi::ec_add_raw(a, b, &AffinePoint::<C, N>::CURVE_PARAMS, out.as_mut_ptr());
            AffinePoint { coords: Some(out.assume_init()), _marker: PhantomData }
        }
    }
}

impl<C: SWCurveConfig<N>, const N: usize> AddAssign<&Self> for AffinePoint<C, N> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        let Some(b_xy) = &rhs.coords else { return };
        let Some(a_xy) = &mut self.coords else {
            *self = *rhs;
            return;
        };

        if a_xy[0] == b_xy[0] {
            if a_xy[1] != b_xy[1] || a_xy[1].is_zero() {
                self.coords = None;
                return;
            }
            self.double_assign();
            return;
        }

        let ptr = core::ptr::from_mut(a_xy);
        unsafe { ffi::ec_add_raw(ptr, b_xy, &Self::CURVE_PARAMS, ptr) };
    }
}

impl<C: SWCurveConfig<N>, const N: usize> Neg for &AffinePoint<C, N> {
    type Output = AffinePoint<C, N>;

    #[inline]
    fn neg(self) -> AffinePoint<C, N> {
        match self.xy() {
            None => AffinePoint::IDENTITY,
            Some((x, y)) => AffinePoint::new_unchecked(x, -&y),
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

impl<C: SWCurveConfig<N>, const N: usize> SubAssign<&Self> for AffinePoint<C, N> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        self.add_assign(&(-rhs));
    }
}

impl<C: SWCurveConfig<N>, const N: usize> AffinePoint<C, N> {
    /// Computes `self = [scalar]a` via MSB-first double-and-add.
    ///
    /// Accepts any point on the curve (not necessarily in the prime-order subgroup) and any
    /// non-negative scalar (including values >= group order).
    #[inline]
    pub(crate) fn mul_into(&mut self, a: &Self, scalar: &BigInt<N>) {
        self.coords = None;
        if a.is_identity() {
            return;
        }
        for i in (0..scalar.bits()).rev() {
            self.double_assign();
            if scalar.bit(i) {
                self.add_assign(a);
            }
        }
    }
}

impl<C: SWCurveConfig<N>, const N: usize, T: AsRef<Unreduced<C::ScalarFieldConfig, N>>> Mul<&T>
    for &AffinePoint<C, N>
{
    type Output = AffinePoint<C, N>;

    #[inline]
    fn mul(self, scalar: &T) -> Self::Output {
        let mut result = AffinePoint::IDENTITY;
        result.mul_into(self, scalar.as_ref().as_bigint());
        result
    }
}

impl<C: SWCurveConfig<N>, const N: usize, T: AsRef<Unreduced<C::ScalarFieldConfig, N>>>
    MulAssign<&T> for AffinePoint<C, N>
{
    #[inline]
    fn mul_assign(&mut self, scalar: &T) {
        let temp = *self;
        self.mul_into(&temp, scalar.as_ref().as_bigint());
    }
}
