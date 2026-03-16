use super::{AffinePoint, SWCurveConfig};
use crate::Unreduced;
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

impl<C: SWCurveConfig<N>, const N: usize> Add for &AffinePoint<C, N> {
    type Output = AffinePoint<C, N>;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        let mut result = AffinePoint::IDENTITY;
        result.add_into(self, rhs);
        result
    }
}

impl<C: SWCurveConfig<N>, const N: usize> Sub for &AffinePoint<C, N> {
    type Output = AffinePoint<C, N>;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        let mut result = AffinePoint::IDENTITY;
        result.sub_into(self, rhs);
        result
    }
}

impl<C: SWCurveConfig<N>, const N: usize> AddAssign<&Self> for AffinePoint<C, N> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        let temp = *self;
        self.add_into(&temp, rhs);
    }
}

impl<C: SWCurveConfig<N>, const N: usize> SubAssign<&Self> for AffinePoint<C, N> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        let temp = *self;
        self.sub_into(&temp, rhs);
    }
}

impl<C: SWCurveConfig<N>, const N: usize, T: AsRef<Unreduced<C::ScalarFieldConfig, N>>> Mul<&T>
    for &AffinePoint<C, N>
{
    type Output = AffinePoint<C, N>;

    #[inline]
    fn mul(self, scalar: &T) -> Self::Output {
        let mut result = AffinePoint::IDENTITY;
        result.mul_into(self, scalar.as_ref());
        result
    }
}

impl<C: SWCurveConfig<N>, const N: usize, T: AsRef<Unreduced<C::ScalarFieldConfig, N>>>
    MulAssign<&T> for AffinePoint<C, N>
{
    #[inline]
    fn mul_assign(&mut self, scalar: &T) {
        let temp = *self;
        self.mul_into(&temp, scalar.as_ref());
    }
}
