//! Bare-bones ECDSA signing and verification.
//!
//! The caller provides the message hash as a big-endian byte slice (e.g. a SHA-256 digest) and a
//! cryptographically secure random nonce for signing. No hash functions or RNG are included.
//!
//! # Security
//!
//! Nonce reuse or predictable nonces leak the private key.

use crate::{
    AffinePoint, SWCurveConfig, Unreduced,
    curve::{BaseField, ScalarField},
};

/// An ECDSA signature `(r, s)` over curve `C`.
#[derive(educe::Educe)]
#[educe(Clone, PartialEq, Eq)]
#[must_use]
pub struct Signature<C: SWCurveConfig<N>, const N: usize> {
    r: ScalarField<C, N>,
    s: ScalarField<C, N>,
}

impl<C: SWCurveConfig<N>, const N: usize> core::fmt::Debug for Signature<C, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Signature").field("r", &self.r).field("s", &self.s).finish()
    }
}

impl<C: SWCurveConfig<N>, const N: usize> Signature<C, N> {
    /// Creates a signature from `(r, s)` components. Returns `None` if either is zero.
    #[inline]
    pub const fn new(r: ScalarField<C, N>, s: ScalarField<C, N>) -> Option<Self> {
        if r.is_zero() || s.is_zero() {
            return None;
        }
        Some(Self { r, s })
    }

    /// Returns the `r` component (x-coordinate of `[k]G`, reduced mod n).
    #[inline]
    pub const fn r(&self) -> &ScalarField<C, N> {
        &self.r
    }

    /// Returns the `s` component.
    #[inline]
    pub const fn s(&self) -> &ScalarField<C, N> {
        &self.s
    }

    /// Decomposes the signature into its `(r, s)` components.
    #[inline]
    pub const fn into_parts(self) -> (ScalarField<C, N>, ScalarField<C, N>) {
        (self.r, self.s)
    }

    /// Signs a message hash with private key `d` and nonce `k`.
    ///
    /// `hash` is the big-endian digest output (e.g. SHA-256), reduced mod n to produce the scalar
    /// `z`. Returns `None` if the nonce produces `r == 0` or `s == 0` (retry with a different
    /// nonce). The caller must ensure `k` is unique and unpredictable per signature - nonce reuse
    /// leaks the private key.
    ///
    /// # Panics
    ///
    /// Panics if `d` or `k` is zero.
    pub fn sign(d: &ScalarField<C, N>, k: &ScalarField<C, N>, hash: &[u8]) -> Option<Self> {
        assert!(!d.is_zero(), "private key d must be nonzero");
        assert!(!k.is_zero(), "nonce k must be nonzero");

        let z = ScalarField::<C, N>::from_be_bytes_mod_order(hash);

        // R = [k]G
        let r_pt = &AffinePoint::<C, N>::GENERATOR * k;
        let (x, _) = r_pt.xy().expect("[k]G is not identity for nonzero k");

        // r = R.x mod n
        let r = base_to_scalar::<C, N>(x);
        if r.is_zero() {
            return None;
        }

        // s = k⁻¹ * (z + r * d) mod n
        let k_inv = k.as_unreduced().inverse();
        let mut s = r.as_unreduced() * d;
        s += &z;
        s *= &k_inv;
        let s = s.check();
        if s.is_zero() {
            return None;
        }

        Some(Self { r, s })
    }

    /// Verifies this signature against a message hash and public key `pubkey`.
    ///
    /// `hash` is the big-endian digest output, reduced mod n to produce the scalar `z`.
    /// The caller should ensure `pubkey` is a valid curve point (e.g. constructed via
    /// [`AffinePoint::new`]).
    pub fn verify(&self, pubkey: &AffinePoint<C, N>, hash: &[u8]) -> bool {
        let z = ScalarField::<C, N>::from_be_bytes_mod_order(hash);

        // u1 = z * s⁻¹, u2 = r * s⁻¹
        let s_inv = self.s.as_unreduced().inverse();
        let u1 = &s_inv * &z;
        let u2 = &s_inv * &self.r;

        // R' = [u1]G + [u2]Q
        let r_pt = &(&AffinePoint::GENERATOR * &u1) + &(pubkey * &u2);

        // accept iff R'.x mod n == r
        let Some((rx, _)) = r_pt.xy() else {
            return false;
        };
        base_to_scalar::<C, N>(rx) == self.r
    }
}

/// Interprets a base field element as a scalar, reducing mod n.
///
/// Uses `reduce()` (not `check()`) because the base field value may legitimately exceed the
/// scalar field modulus - this is a cross-field conversion, not a bigint2 result check.
fn base_to_scalar<C: SWCurveConfig<N>, const N: usize>(x: BaseField<C, N>) -> ScalarField<C, N> {
    // ECDSA requires p < 2n so that x mod n has at most 2 preimages. We check the stricter
    // bit_len(n) >= bit_len(p) which is simpler and sufficient for all standard curves.
    const {
        assert!(
            ScalarField::<C, N>::MODULUS_BIT_LEN >= BaseField::<C, N>::MODULUS_BIT_LEN,
            "ECDSA requires scalar and base fields to have similar bit length",
        );
    }
    Unreduced::<C::ScalarFieldConfig, N>::from_bigint(x.to_bigint()).reduce()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{curves::secp256k1, fp};

    type Fr = secp256k1::Fr;
    type Affine = secp256k1::Affine;
    type Sig = Signature<secp256k1::Config, 8>;

    const HASH: &[u8] = &[0xde, 0xad, 0xbe, 0xef];

    #[test]
    fn sign_verify_roundtrip() {
        let d: Fr = fp!("0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let pubkey = &Affine::GENERATOR * &d;
        let k: Fr = fp!("0xa6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60");

        let sig = Sig::sign(&d, &k, HASH).unwrap();
        assert!(sig.verify(&pubkey, HASH));
    }

    #[test]
    fn wrong_message_rejects() {
        let d: Fr = fp!("0x1");
        let pubkey = &Affine::GENERATOR * &d;
        let k: Fr = fp!("0x2");

        let sig = Sig::sign(&d, &k, HASH).unwrap();
        assert!(!sig.verify(&pubkey, &[0xde, 0xad, 0xbe, 0xee]));
    }

    #[test]
    fn wrong_pubkey_rejects() {
        let d: Fr = fp!("0x1");
        let k: Fr = fp!("0x2");

        let sig = Sig::sign(&d, &k, HASH).unwrap();
        let wrong_pk = &Affine::GENERATOR * &Fr::from_u32(2);
        assert!(!sig.verify(&wrong_pk, HASH));
    }

    #[test]
    fn new_rejects_zero_components() {
        assert!(Sig::new(Fr::ZERO, Fr::ONE).is_none());
        assert!(Sig::new(Fr::ONE, Fr::ZERO).is_none());
        assert!(Sig::new(Fr::ZERO, Fr::ZERO).is_none());
        assert!(Sig::new(Fr::ONE, Fr::ONE).is_some());
    }
}
