use super::{AffinePoint, SWCurveConfig, ScalarField};
use crate::field::FieldArith;
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

impl<C: SWCurveConfig<N>, const N: usize> Add<&AffinePoint<C, N>> for &AffinePoint<C, N>
where
    [u32; N]: FieldArith,
{
    type Output = AffinePoint<C, N>;

    #[inline]
    fn add(self, rhs: &AffinePoint<C, N>) -> Self::Output {
        let mut result = AffinePoint::IDENTITY;
        result.add_into(self, rhs);
        result
    }
}

impl<C: SWCurveConfig<N>, const N: usize> Add for AffinePoint<C, N>
where
    [u32; N]: FieldArith,
{
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        let mut result = Self::IDENTITY;
        result.add_into(&self, &rhs);
        result
    }
}

impl<C: SWCurveConfig<N>, const N: usize> AddAssign<&Self> for AffinePoint<C, N>
where
    [u32; N]: FieldArith,
{
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        let temp = *self;
        self.add_into(&temp, rhs);
    }
}

impl<C: SWCurveConfig<N>, const N: usize> Sub<&AffinePoint<C, N>> for &AffinePoint<C, N>
where
    [u32; N]: FieldArith,
{
    type Output = AffinePoint<C, N>;

    #[inline]
    fn sub(self, rhs: &AffinePoint<C, N>) -> Self::Output {
        let mut result = AffinePoint::IDENTITY;
        result.sub_into(self, rhs);
        result
    }
}

impl<C: SWCurveConfig<N>, const N: usize> Sub for AffinePoint<C, N>
where
    [u32; N]: FieldArith,
{
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        let mut result = Self::IDENTITY;
        result.sub_into(&self, &rhs);
        result
    }
}

impl<C: SWCurveConfig<N>, const N: usize> SubAssign<&Self> for AffinePoint<C, N>
where
    [u32; N]: FieldArith,
{
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        let temp = *self;
        self.sub_into(&temp, rhs);
    }
}

impl<C: SWCurveConfig<N>, const N: usize> Mul<&ScalarField<C, N>> for &AffinePoint<C, N>
where
    [u32; N]: FieldArith,
{
    type Output = AffinePoint<C, N>;

    #[inline]
    fn mul(self, scalar: &ScalarField<C, N>) -> Self::Output {
        let mut result = AffinePoint::IDENTITY;
        result.mul_into(self, scalar);
        result
    }
}

impl<C: SWCurveConfig<N>, const N: usize> Mul<ScalarField<C, N>> for AffinePoint<C, N>
where
    [u32; N]: FieldArith,
{
    type Output = Self;

    #[inline]
    fn mul(self, scalar: ScalarField<C, N>) -> Self::Output {
        let mut result = Self::IDENTITY;
        result.mul_into(&self, &scalar);
        result
    }
}

impl<C: SWCurveConfig<N>, const N: usize> MulAssign<&ScalarField<C, N>> for AffinePoint<C, N>
where
    [u32; N]: FieldArith,
{
    #[inline]
    fn mul_assign(&mut self, scalar: &ScalarField<C, N>) {
        let temp = *self;
        self.mul_into(&temp, scalar);
    }
}
