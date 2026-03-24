//! Bare-bones ECDSA signing and verification.
//!
//! The caller provides the message hash as a big-endian byte slice (e.g. a SHA-256 digest) and a
//! cryptographically secure random nonce for signing. No hash functions or RNG are included.
//!
//! # Example
//!
//! ```no_run
//! # use risc0_crypto::{AffinePoint, ecdsa::Signature, curves::secp256k1::{self, Fr, Affine}};
//! #
//! let d: Fr = /* private key */
//! # Fr::ONE;
//! let k: Fr = /* cryptographically secure random nonce */
//! # Fr::ONE;
//! let hash: &[u8] = /* message digest, e.g. SHA-256 output */
//! # &[0u8; 32];
//!
//! // sign
//! let sig = Signature::<secp256k1::Config, 8>::sign(&d, &k, hash).unwrap();
//!
//! // verify
//! let pubkey = &Affine::GENERATOR * &d;
//! assert!(sig.verify(&pubkey, hash));
//! ```
//!
//! # Curve compatibility
//!
//! ECDSA requires the scalar field order `n` to be close in size to the base field order `p`.
//! Curves where `bit_len(n) < bit_len(p)` (e.g. BLS12-381) are rejected at compile time:
//!
//! ```compile_fail
//! # use risc0_crypto::{ecdsa::Signature, curves::bls12_381::{self, Fr}};
//! #
//! type Sig = Signature<bls12_381::Config, 12>;
//! let _ = Sig::sign(&Fr::ONE, &Fr::ONE, &[0xff]);
//! ```
//!
//! # Security
//!
//! Nonce reuse or predictable nonces leak the private key.

use crate::{
    AffinePoint, CurveConfig, Fp,
    curve::{BaseField, ScalarField},
};

/// An ECDSA signature `(r, s)` over curve `C`.
#[derive(educe::Educe)]
#[educe(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct Signature<C: CurveConfig<N>, const N: usize> {
    r: ScalarField<C, N>,
    s: ScalarField<C, N>,
}

impl<C: CurveConfig<N>, const N: usize> Signature<C, N> {
    /// Creates a signature from `(r, s)` components. Returns `None` if either is zero.
    #[inline]
    pub const fn new(r: ScalarField<C, N>, s: ScalarField<C, N>) -> Option<Self> {
        if r.is_zero() || s.is_zero() {
            return None;
        }
        Some(Self { r, s })
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
    /// Panics if `k` is zero.
    pub fn sign(d: &ScalarField<C, N>, k: &ScalarField<C, N>, hash: &[u8]) -> Option<Self> {
        assert!(!k.is_zero(), "nonce k must be nonzero");

        // R = [k]G
        let r_pt = &AffinePoint::<C, N>::GENERATOR * k;
        // SAFETY: [k]G is not identity for nonzero k
        let (x, _) = unsafe { r_pt.xy().unwrap_unchecked() };

        // r = R.x mod n
        let r = base_to_scalar::<C, N>(x);
        if r.is_zero() {
            return None;
        }

        let z = ScalarField::<C, N>::from_be_bytes_mod_order(hash);

        // s = k⁻¹ * (r * d + z) mod n
        let k_inv = k.as_unverified().inverse();
        let s = (&k_inv * &(&(r.as_unverified() * d) + &z)).check();
        if s.is_zero() {
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

    /// Verifies this signature against a message hash and public key `pubkey`.
    ///
    /// `hash` is the big-endian digest output, reduced mod n to produce the scalar `z`.
    /// `pubkey` must be in the prime-order subgroup (e.g. constructed via
    /// [`AffinePoint::new_in_subgroup`]).
    pub fn verify(&self, pubkey: &AffinePoint<C, N>, hash: &[u8]) -> bool {
        let z = ScalarField::<C, N>::from_be_bytes_mod_order(hash);

        // u1 = z * s⁻¹, u2 = r * s⁻¹ (s is nonzero by construction)
        let s_inv = self.s.as_unverified().inverse();
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

    /// Normalizes into "low S" form as described in [BIP 0062: Dealing with Malleability][1].
    /// Returns `None` if already normalized.
    ///
    /// [1]: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
    #[inline]
    pub fn normalize_s(&self) -> Option<Self> {
        if self.s_is_high() { Some(Self { r: self.r, s: -&self.s }) } else { None }
    }

    /// Returns the signature in "low S" form, negating `s` if needed. See
    /// [`normalize_s`](Self::normalize_s).
    #[inline]
    pub fn normalized_s(self) -> Self {
        self.normalize_s().unwrap_or(self)
    }

    /// Returns `true` if `s > n/2` (high-s).
    fn s_is_high(&self) -> bool {
        // s > n/2 iff s > n - s (as integers), avoiding a stored half-order constant
        self.s.as_bigint() > (-&self.s).as_bigint()
    }
}

/// Interprets a base field element as a scalar, reducing mod n.
fn base_to_scalar<C: CurveConfig<N>, const N: usize>(x: BaseField<C, N>) -> ScalarField<C, N> {
    // ECDSA requires p < 2n so that x mod n has at most 2 preimages. We check the stricter
    // bit_len(n) >= bit_len(p) which is simpler and sufficient for all standard curves.
    const {
        assert!(
            ScalarField::<C, N>::MODULUS_BIT_LEN >= BaseField::<C, N>::MODULUS_BIT_LEN,
            "ECDSA requires scalar and base fields to have similar bit length",
        );
    }
    Fp::<C::ScalarFieldConfig, N>::reduce_from_bigint(x.to_bigint())
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
    fn new_rejects_zero_components() {
        assert!(Sig::new(Fr::ZERO, Fr::ONE).is_none());
        assert!(Sig::new(Fr::ONE, Fr::ZERO).is_none());
        assert!(Sig::new(Fr::ZERO, Fr::ZERO).is_none());
        assert!(Sig::new(Fr::ONE, Fr::ONE).is_some());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let d: Fr = fp!("0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let pubkey = &Affine::GENERATOR * &d;
        let k: Fr = fp!("0xa6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60");

        let sig = Sig::sign(&d, &k, HASH).unwrap();
        assert!(sig.verify(&pubkey, HASH));
    }

    #[test]
    fn sign_with_zero_private_key() {
        let d: Fr = Fr::ZERO;
        let pubkey = &Affine::GENERATOR * &d;
        let k: Fr = Fr::ONE;

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
    fn normalize_s() {
        let d: Fr = fp!("0x1");
        let k: Fr = fp!("0x2");
        let sig = Sig::sign(&d, &k, HASH).unwrap();

        let normalized = sig.normalized_s();
        assert!(normalized.normalize_s().is_none(), "already normalized");
        assert!(normalized.verify(&(&Affine::GENERATOR * &d), HASH));

        // manually flip s to get high-s, then normalize back
        let high_s = Sig::new(*normalized.r(), -normalized.s()).unwrap();
        assert!(high_s.normalize_s().is_some());
        assert_eq!(high_s.normalized_s(), normalized);
    }
}
