use risc0_bigint2::field::{
    modadd_256, modadd_384, modinv_256, modinv_384, modmul_256, modmul_384, modsub_256, modsub_384,
    unchecked,
};

mod private {
    pub trait Sealed {}
    impl Sealed for [u32; 8] {}
    impl Sealed for [u32; 12] {}
}

/// A trait that dispatches modular arithmetic by array width.
///
/// Sealed - cannot be implemented outside this crate. Implemented for `[u32; 8]` (256-bit) and
/// `[u32; 12]` (384-bit).
pub trait FieldArith: private::Sealed {
    #[doc(hidden)]
    fn add(a: &Self, b: &Self, m: &Self, r: &mut Self);
    #[doc(hidden)]
    fn add_unchecked(a: &Self, b: &Self, m: &Self, r: &mut Self);
    #[doc(hidden)]
    fn sub(a: &Self, b: &Self, m: &Self, r: &mut Self);
    #[doc(hidden)]
    fn sub_unchecked(a: &Self, b: &Self, m: &Self, r: &mut Self);
    #[doc(hidden)]
    fn mul(a: &Self, b: &Self, m: &Self, r: &mut Self);
    #[doc(hidden)]
    fn mul_unchecked(a: &Self, b: &Self, m: &Self, r: &mut Self);
    #[doc(hidden)]
    fn inv(a: &Self, m: &Self, r: &mut Self);
    #[doc(hidden)]
    fn inv_unchecked(a: &Self, m: &Self, r: &mut Self);
}

impl FieldArith for [u32; 8] {
    #[inline]
    fn add(a: &Self, b: &Self, m: &Self, r: &mut Self) {
        modadd_256(a, b, m, r)
    }
    #[inline]
    fn add_unchecked(a: &Self, b: &Self, m: &Self, r: &mut Self) {
        unchecked::modadd_256(a, b, m, r)
    }
    #[inline]
    fn sub(a: &Self, b: &Self, m: &Self, r: &mut Self) {
        modsub_256(a, b, m, r)
    }
    #[inline]
    fn sub_unchecked(a: &Self, b: &Self, m: &Self, r: &mut Self) {
        unchecked::modsub_256(a, b, m, r)
    }
    #[inline]
    fn mul(a: &Self, b: &Self, m: &Self, r: &mut Self) {
        modmul_256(a, b, m, r)
    }
    #[inline]
    fn mul_unchecked(a: &Self, b: &Self, m: &Self, r: &mut Self) {
        unchecked::modmul_256(a, b, m, r)
    }
    #[inline]
    fn inv(a: &Self, m: &Self, r: &mut Self) {
        modinv_256(a, m, r)
    }
    #[inline]
    fn inv_unchecked(a: &Self, m: &Self, r: &mut Self) {
        unchecked::modinv_256(a, m, r)
    }
}

impl FieldArith for [u32; 12] {
    #[inline]
    fn add(a: &Self, b: &Self, m: &Self, r: &mut Self) {
        modadd_384(a, b, m, r)
    }
    #[inline]
    fn add_unchecked(a: &Self, b: &Self, m: &Self, r: &mut Self) {
        unchecked::modadd_384(a, b, m, r)
    }
    #[inline]
    fn sub(a: &Self, b: &Self, m: &Self, r: &mut Self) {
        modsub_384(a, b, m, r)
    }
    #[inline]
    fn sub_unchecked(a: &Self, b: &Self, m: &Self, r: &mut Self) {
        unchecked::modsub_384(a, b, m, r)
    }
    #[inline]
    fn mul(a: &Self, b: &Self, m: &Self, r: &mut Self) {
        modmul_384(a, b, m, r)
    }
    #[inline]
    fn mul_unchecked(a: &Self, b: &Self, m: &Self, r: &mut Self) {
        unchecked::modmul_384(a, b, m, r)
    }
    #[inline]
    fn inv(a: &Self, m: &Self, r: &mut Self) {
        modinv_384(a, m, r)
    }
    #[inline]
    fn inv_unchecked(a: &Self, m: &Self, r: &mut Self) {
        unchecked::modinv_384(a, m, r)
    }
}
