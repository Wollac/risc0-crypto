pub(crate) mod ops;
pub use ops::FieldArith;

use crate::BigInt;

/// A trait that defines the configuration of a prime field [`Fp<P, N>`](Fp).
///
/// Implement this trait to introduce a new field - only [`MODULUS`](Self::MODULUS) is required.
pub trait PrimeFieldConfig<const N: usize>: Send + Sync + 'static + Sized
where
    [u32; N]: FieldArith,
{
    /// The field modulus `p`.
    const MODULUS: BigInt<N>;

    /// Additive identity of the field, i.e. the element `e` such that, for all elements `f` of the
    /// field, `e + f = f`.
    const ZERO: Fp<Self, N> = Fp::from_bigint_unchecked(BigInt::ZERO);

    /// Multiplicative identity of the field, i.e. the element `e` such that, for all elements `f`
    /// of the field, `e * f = f`.
    ///
    /// Defaults to little-endian `[1, 0, …]`. Override for alternative representations
    /// (e.g. Montgomery form where ONE = R mod p).
    const ONE: Fp<Self, N> = Fp::from_bigint_unchecked(BigInt::from_u32(1));
}

/// An element of the prime field defined by [`P::MODULUS`](PrimeFieldConfig::MODULUS).
///
/// # Checked vs unchecked operations
///
/// **Checked** operations (e.g. [`add`](Self::add), [`mul`](Self::mul)) produce canonical results
/// in `[0, p)`. **Unchecked** operations (e.g. [`add_unchecked`](Self::add_unchecked)) may return
/// unreduced values equivalent to `v + k·p` for some small `k`.
///
/// Both checked and unchecked operations accept unreduced inputs, so unchecked results can be
/// freely chained into further arithmetic. However, **never compare unreduced values directly** -
/// limb-level comparisons (`==`, [`is_zero`](Self::is_zero), [`is_valid`](Self::is_valid)) on
/// unreduced values are unsound in a ZK context because a dishonest prover can choose between
/// equivalent representations (e.g. returning `p` instead of `0`). Always feed unchecked results
/// through a checked operation or [`reduce`](Self::reduce) before any comparison.
#[derive(educe::Educe)]
#[educe(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Fp<P, const N: usize> {
    limbs: [u32; N],
    _marker: core::marker::PhantomData<P>,
}

impl<P, const N: usize> core::fmt::Debug for Fp<P, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Fp").field(&self.to_bigint()).finish()
    }
}

pub type Fp256<P> = Fp<P, 8>;
pub type Fp384<P> = Fp<P, 12>;

impl<P, const N: usize> Fp<P, N> {
    /// Creates a field element from a [`BigInt`] without checking `< p`.
    #[inline]
    pub const fn from_bigint_unchecked(b: BigInt<N>) -> Self {
        Self { limbs: b.0, _marker: core::marker::PhantomData }
    }

    #[inline]
    pub const fn to_bigint(self) -> BigInt<N> {
        BigInt(self.limbs)
    }

    /// Returns the limbs as an owned array.
    #[inline]
    pub(crate) const fn to_limbs(self) -> [u32; N] {
        self.limbs
    }

    /// Returns a reference to the underlying limb array.
    #[inline]
    pub(crate) const fn as_limbs(&self) -> &[u32; N] {
        &self.limbs
    }

    /// Returns `true` if all limbs are zero.
    #[inline]
    pub const fn is_zero(&self) -> bool {
        self.to_bigint().is_zero()
    }
}

impl<P: PrimeFieldConfig<N>, const N: usize> Fp<P, N>
where
    [u32; N]: FieldArith,
{
    /// Additive identity (`0`).
    pub const ZERO: Self = P::ZERO;
    /// Multiplicative identity (`1`).
    pub const ONE: Self = P::ONE;

    /// Shift factor for processing byte slices in chunks of `N * 4 - 1` bytes.
    const CHUNK_BASE: Self = {
        let mut limbs = [0u32; N];
        limbs[N - 1] = 1 << (u32::BITS - 8);
        Self::from_bigint_unchecked(BigInt::new(limbs))
    };

    /// Returns `true` if the limbs represent a canonical field element (i.e. `< p`).
    #[inline]
    pub const fn is_valid(&self) -> bool {
        BigInt(self.limbs).is_less(&P::MODULUS)
    }

    /// Creates a field element from a [`BigInt`], returning `None` if the value is `>= p`.
    ///
    /// This is a const fn, so when used via the [`fp!`](crate::fp) macro in const context, an
    /// out-of-range value becomes a compile-time error.
    #[inline]
    pub const fn from_bigint(b: BigInt<N>) -> Option<Self> {
        let fp = Self::from_bigint_unchecked(b);
        match fp.is_valid() {
            true => Some(fp),
            false => None,
        }
    }

    /// Creates a field element from a `u32`. Panics if `val >= p`.
    #[inline]
    pub const fn from_u32(val: u32) -> Self {
        match Self::from_bigint(BigInt::from_u32(val)) {
            Some(fp) => fp,
            None => panic!("from_u32: value exceeds field modulus"),
        }
    }

    /// Reduces a potentially unreduced value to its canonical representative in `[0, p)`.
    ///
    /// If the value is already `< p`, returns it with no syscalls.
    // TODO: fallback uses add(x, 0) to reduce, consider more performant alternatives
    // For fields where 2p overflows the container (secp256k1, secp256r1), unreduced values
    // can only be v + k·p for small k, so a single subtract-and-check loop would suffice
    // without any syscalls.
    #[must_use]
    #[inline]
    pub fn reduce(self) -> Self {
        if self.is_valid() {
            return self;
        }
        let mut r = Self::ZERO;
        r.add(&self, &Self::ZERO);
        r
    }

    /// Computes `self = a + b mod p`.
    #[inline]
    pub fn add(&mut self, a: &Self, b: &Self) {
        <[u32; N]>::add(&a.limbs, &b.limbs, &P::MODULUS.0, &mut self.limbs);
    }

    /// Computes `self = a - b mod p`.
    #[inline]
    pub fn sub(&mut self, a: &Self, b: &Self) {
        <[u32; N]>::sub(&a.limbs, &b.limbs, &P::MODULUS.0, &mut self.limbs);
    }

    /// Computes `self = a * b mod p`.
    #[inline]
    pub fn mul(&mut self, a: &Self, b: &Self) {
        <[u32; N]>::mul(&a.limbs, &b.limbs, &P::MODULUS.0, &mut self.limbs);
    }

    /// Computes `self = a⁻¹ mod p`.
    ///
    /// If `a` is zero the result is undefined (the R0VM circuit behavior is unspecified for
    /// this case). A `debug_assert` catches this in debug builds.
    #[inline]
    pub fn inv(&mut self, a: &Self) {
        debug_assert!(!a.reduce().is_zero(), "inverse does not exist for zero");
        <[u32; N]>::inv(&a.limbs, &P::MODULUS.0, &mut self.limbs);
    }

    /// Computes `self = -a mod p`.
    // TODO: could also be p - a via plain subtraction (no syscall), benchmark on R0VM
    #[inline]
    pub fn neg(&mut self, a: &Self) {
        <[u32; N]>::sub(&Self::ZERO.limbs, &a.limbs, &P::MODULUS.0, &mut self.limbs);
    }

    /// Like [`Self::add`], but the result may be unreduced (`v + k·p`).
    #[inline]
    pub fn add_unchecked(&mut self, a: &Self, b: &Self) {
        <[u32; N]>::add_unchecked(&a.limbs, &b.limbs, &P::MODULUS.0, &mut self.limbs);
    }

    /// Like [`Self::sub`], but the result may be unreduced (`v + k·p`).
    #[inline]
    pub fn sub_unchecked(&mut self, a: &Self, b: &Self) {
        <[u32; N]>::sub_unchecked(&a.limbs, &b.limbs, &P::MODULUS.0, &mut self.limbs);
    }

    /// Like [`Self::mul`], but the result may be unreduced (`v + k·p`).
    #[inline]
    pub fn mul_unchecked(&mut self, a: &Self, b: &Self) {
        <[u32; N]>::mul_unchecked(&a.limbs, &b.limbs, &P::MODULUS.0, &mut self.limbs);
    }

    /// Like [`Self::inv`], but the result may be unreduced (`v + k·p`).
    ///
    /// If `a` is zero the result is undefined (see [`Self::inv`]).
    #[inline]
    pub fn inv_unchecked(&mut self, a: &Self) {
        debug_assert!(!a.reduce().is_zero(), "inverse does not exist for zero");
        <[u32; N]>::inv_unchecked(&a.limbs, &P::MODULUS.0, &mut self.limbs);
    }

    /// Like [`Self::neg`], but the result may be unreduced (`v + k·p`).
    #[inline]
    pub fn neg_unchecked(&mut self, a: &Self) {
        <[u32; N]>::sub_unchecked(&Self::ZERO.limbs, &a.limbs, &P::MODULUS.0, &mut self.limbs);
    }

    /// Creates a field element from a big-endian byte slice, reducing modulo `p`.
    ///
    /// When the input fits in `N * 4` bytes and is already `< p`, no syscalls are issued.
    #[inline]
    pub fn from_be_bytes_mod_order(bytes: &[u8]) -> Self {
        if bytes.len() <= N * 4 {
            return Self::from_bigint_unchecked(BigInt::from_be_bytes(bytes)).reduce();
        }

        let chunks = bytes.rchunks_exact(N * 4 - 1);
        let first = chunks.remainder(); // most significant (head in BE)

        let mut result = Self::from_bigint_unchecked(BigInt::from_be_bytes(first));

        let mut temp = Self::ZERO;
        for chunk in chunks.rev() {
            let chunk_val = Self::from_bigint_unchecked(BigInt::from_be_bytes(chunk));
            temp.mul_unchecked(&result, &Self::CHUNK_BASE);
            result.add_unchecked(&temp, &chunk_val);
        }
        // verify result is canonical (honest prover check)
        assert!(result.is_valid());

        result
    }

    /// Creates a field element from a little-endian byte slice, reducing modulo `p`.
    ///
    /// When the input fits in `N * 4` bytes and is already `< p`, no syscalls are issued.
    #[cfg(target_endian = "little")]
    #[inline]
    pub fn from_le_bytes_mod_order(bytes: &[u8]) -> Self {
        if bytes.len() <= N * 4 {
            return Self::from_bigint_unchecked(BigInt::from_le_bytes(bytes)).reduce();
        }

        let chunks = bytes.chunks_exact(N * 4 - 1);
        let first = chunks.remainder(); // most significant (tail in LE)

        let mut result = Self::from_bigint_unchecked(BigInt::from_le_bytes(first));

        let mut temp = Self::ZERO;
        for chunk in chunks.rev() {
            let chunk_val = Self::from_bigint_unchecked(BigInt::from_le_bytes(chunk));
            temp.mul_unchecked(&result, &Self::CHUNK_BASE);
            result.add_unchecked(&temp, &chunk_val);
        }
        // verify result is canonical (honest prover check)
        assert!(result.is_valid());

        result
    }
}

#[cfg(test)]
mod tests {
    use super::{Fp256, PrimeFieldConfig};
    use crate::BigInt;

    // Test field: F_7 (arbitrary small prime, independent of any curve)
    enum P {}
    impl PrimeFieldConfig<8> for P {
        const MODULUS: BigInt<8> = BigInt::from_u32(7);
    }
    type F = Fp256<P>;

    /// Applies an Fp operation and returns the result.
    macro_rules! fp {
        ($op:ident, $a:expr, $b:expr) => {{
            let mut r = F::ZERO;
            r.$op($a, $b);
            r
        }};
        ($op:ident, $a:expr) => {{
            let mut r = F::ZERO;
            r.$op($a);
            r
        }};
    }

    #[test]
    fn from_limbs_validation() {
        let v = BigInt::from_u32(4);
        assert!(F::from_bigint(v).is_some());
        assert_eq!(F::from_bigint(v).unwrap().to_bigint(), v);
        assert!(F::from_bigint(P::MODULUS).is_none());
        assert!(F::from_bigint(BigInt::from_u32(8)).is_none());
    }

    #[test]
    fn field_axioms() {
        let (a, b, c) = (F::from_u32(3), F::from_u32(5), F::from_u32(2));

        // Commutativity
        assert_eq!(fp!(add, &a, &b), fp!(add, &b, &a));
        assert_eq!(fp!(mul, &a, &b), fp!(mul, &b, &a));

        // Associativity
        assert_eq!(fp!(add, &fp!(add, &a, &b), &c), fp!(add, &a, &fp!(add, &b, &c)));
        assert_eq!(fp!(mul, &fp!(mul, &a, &b), &c), fp!(mul, &a, &fp!(mul, &b, &c)));

        // Identity
        assert_eq!(fp!(add, &a, &F::ZERO), a);
        assert_eq!(fp!(mul, &a, &F::ONE), a);

        // Inverse
        assert_eq!(fp!(add, &a, &fp!(neg, &a)), F::ZERO);
        assert_eq!(fp!(mul, &a, &fp!(inv, &a)), F::ONE);

        // Distributivity
        assert_eq!(fp!(mul, &a, &fp!(add, &b, &c)), fp!(add, &fp!(mul, &a, &b), &fp!(mul, &a, &c)));
    }

    #[test]
    fn edge_cases() {
        let a = F::from_u32(3);

        assert_eq!(fp!(neg, &F::ZERO), F::ZERO);
        assert_eq!(fp!(sub, &a, &a), F::ZERO);
        assert_eq!(fp!(mul, &a, &F::ZERO), F::ZERO);
    }

    #[test]
    fn from_be_bytes_mod_order() {
        // empty → zero
        assert_eq!(F::from_be_bytes_mod_order(&[]), F::ZERO);

        // fast path: below, equal to, and above modulus
        assert_eq!(F::from_be_bytes_mod_order(&[3]), F::from_u32(3));
        assert_eq!(F::from_be_bytes_mod_order(&[7]), F::ZERO);
        assert_eq!(F::from_be_bytes_mod_order(&[10]), F::from_u32(3));

        // slow path: (256^64 - 1) mod 7 = 3
        assert_eq!(F::from_be_bytes_mod_order(&[0xff; 64]), F::from_u32(3));
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn from_le_bytes_mod_order() {
        // empty -> zero
        assert_eq!(F::from_le_bytes_mod_order(&[]), F::ZERO);

        // fast path: below, equal to, and above modulus
        assert_eq!(F::from_le_bytes_mod_order(&[3]), F::from_u32(3));
        assert_eq!(F::from_le_bytes_mod_order(&[7]), F::ZERO);
        assert_eq!(F::from_le_bytes_mod_order(&[10]), F::from_u32(3));

        // slow path: (256^64 - 1) mod 7 = 3
        assert_eq!(F::from_le_bytes_mod_order(&[0xff; 64]), F::from_u32(3));

        // LE vs BE: [0x01, 0x02] means 0x0201 in LE, 0x0102 in BE
        assert_eq!(
            F::from_le_bytes_mod_order(&[0x01, 0x02]),
            F::from_be_bytes_mod_order(&[0x02, 0x01]),
        );
    }

    #[test]
    fn checked_ops_accept_unreduced_input() {
        // 3 + 1·p = 10 in limbs, which represents 3 mod 7 but is not canonical.
        let three_unreduced = F::from_bigint_unchecked(BigInt::from_u32(10));
        let two = F::from_u32(2);

        assert_eq!(fp!(add, &three_unreduced, &two), F::from_u32(5));
        assert_eq!(fp!(mul, &three_unreduced, &two), F::from_u32(6));
        assert_eq!(fp!(sub, &three_unreduced, &two), F::from_u32(1));
    }
}
