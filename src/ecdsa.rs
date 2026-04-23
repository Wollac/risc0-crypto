//! ECDSA signing, verification, and public key recovery.
//!
//! The caller provides the message hash as a big-endian byte slice (e.g. a SHA-256 digest) and a
//! cryptographically secure random nonce for signing. No hash functions or RNG are included.
//! The hash is interpreted as a big-endian integer and reduced mod n (the group order).
//! For standard pairings (SHA-256 with 256-bit curves, SHA-384 with 384-bit curves) this
//! matches SEC1 `bits2int`. For non-standard pairings where the hash is wider than the
//! order, the caller should truncate to `ceil(bit_len(n) / 8)` bytes before passing it in.
//!
//! - [`Signature`] - plain `(r, s)` signature with [`sign`](Signature::sign) and
//!   [`verify`](Signature::verify).
//! - [`RecoverableSignature`] - wraps a [`Signature`] with a [`RecoveryId`] that identifies which
//!   public key produced it. [`verify`](RecoverableSignature::verify) checks both the signature and
//!   recovery ID against a provided public key.
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
//! # Ethereum / EIP-2 compatible signatures
//!
//! Ethereum requires low-S normalization ([EIP-2]) and rejects `is_x_reduced` recovery IDs
//! (v must be 27 or 28). Normalize after signing and check:
//!
//! ```no_run
//! # use risc0_crypto::{ecdsa::RecoverableSignature, curves::secp256k1::{self, Fr}};
//! # let (d, k, hash): (Fr, Fr, &[u8]) = (Fr::ONE, Fr::ONE, &[0u8; 32]);
//! #
//! let rsig =
//!     RecoverableSignature::<secp256k1::Config, 8>::sign(&d, &k, hash).unwrap().normalized_s();
//!
//! // Ethereum v = 27 + is_y_odd (is_x_reduced must be false for secp256k1)
//! assert!(!rsig.recovery_id().is_x_reduced());
//! let v = 27u8 + rsig.recovery_id().is_y_odd() as u8;
//! ```
//!
//! [EIP-2]: https://eips.ethereum.org/EIPS/eip-2
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

use crate::{AffinePoint, CurveConfig, FieldConfig, Fp, PrimeCurveConfig, curve::ScalarField};

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

    /// Normalizes into "low S" form as described in [BIP 0062: Dealing with Malleability][1].
    /// Returns `None` if already normalized.
    ///
    /// [1]: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
    pub fn normalize_s(&self) -> Option<Self> {
        if self.s.is_high() { Some(Self { r: self.r, s: -&self.s }) } else { None }
    }

    /// Returns the signature in "low S" form, negating `s` if needed. See
    /// [`normalize_s`](Self::normalize_s).
    #[inline]
    pub fn normalized_s(self) -> Self {
        self.normalize_s().unwrap_or(self)
    }
}

// --- ECDSA sign/verify requires prime-field base coordinates ---

impl<P: FieldConfig<N>, C: PrimeCurveConfig<N, BaseFieldConfig = P>, const N: usize>
    Signature<C, N>
{
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
        let (r, s, ..) = sign_raw::<P, C, N>(d, k, hash)?;
        Some(Self { r, s })
    }

    /// Reconstructs the candidate nonce point `R' = [z*s⁻¹]G + [r*s⁻¹]Q`.
    fn reconstruct_r(&self, pubkey: &AffinePoint<C, N>, hash: &[u8]) -> AffinePoint<C, N> {
        let z = ScalarField::<C, N>::from_be_bytes_mod_order(hash);

        // u1 = z * s⁻¹, u2 = r * s⁻¹ (s is nonzero by construction)
        let s_inv = self.s.as_unverified().inverse();
        let u1 = &s_inv * &z;
        let u2 = &s_inv * &self.r;

        // R' = [u1]G + [u2]Q
        AffinePoint::double_scalar_mul(
            u1.check_ref(),
            &AffinePoint::GENERATOR,
            u2.check_ref(),
            pubkey,
        )
    }

    /// Verifies this signature against a message hash and public key `pubkey`.
    pub fn verify(&self, pubkey: &AffinePoint<C, N>, hash: &[u8]) -> bool {
        let Some((rx, _)) = self.reconstruct_r(pubkey, hash).xy() else {
            return false;
        };
        base_to_scalar::<P, C, N>(rx) == self.r
    }
}

/// Identifies which of up to 4 possible public keys produced a given ECDSA signature.
///
/// Encodes two bits of information about the nonce point `R = [k]G`:
/// - **bit 0** (`is_y_odd`): whether `R.y` was odd
/// - **bit 1** (`is_x_reduced`): whether `R.x` (a base field element) exceeded the scalar field
///   order `n` and was reduced. For curves like secp256k1 where `p - n` is tiny this is
///   astronomically rare, but the bit is needed for correctness.
#[derive(Copy, Clone, PartialEq, Eq)]
#[must_use]
pub struct RecoveryId(u8);

impl core::fmt::Debug for RecoveryId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoveryId")
            .field("y_odd", &self.is_y_odd())
            .field("x_reduced", &self.is_x_reduced())
            .finish()
    }
}

impl RecoveryId {
    /// Creates a recovery ID from its two component flags.
    #[inline]
    pub const fn new(is_y_odd: bool, is_x_reduced: bool) -> Self {
        Self((is_x_reduced as u8) << 1 | is_y_odd as u8)
    }

    /// Creates a recovery ID from a raw byte. Returns `None` if `byte > 3`.
    #[inline]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        if byte > 3 { None } else { Some(Self(byte)) }
    }

    /// Returns the raw byte value (0-3).
    #[inline]
    pub const fn to_byte(self) -> u8 {
        self.0
    }

    /// Was the y-coordinate of `R = [k]G` odd?
    #[inline]
    pub const fn is_y_odd(self) -> bool {
        self.0 & 1 != 0
    }

    /// Did `R.x` exceed the scalar field order before reduction to produce `r`?
    #[inline]
    pub const fn is_x_reduced(self) -> bool {
        self.0 >> 1 != 0
    }

    /// Returns a new recovery ID with the y-parity bit flipped.
    const fn flip_y_parity(self) -> Self {
        Self(self.0 ^ 1)
    }
}

/// An ECDSA signature with a [`RecoveryId`] that identifies which public key produced it.
///
/// Wraps a [`Signature`] and its associated recovery ID. Methods like
/// [`normalize_s`](Self::normalize_s) keep the two in sync automatically.
#[derive(educe::Educe)]
#[educe(Clone, PartialEq, Eq)]
#[must_use]
pub struct RecoverableSignature<C: CurveConfig<N>, const N: usize> {
    sig: Signature<C, N>,
    recovery_id: RecoveryId,
}

impl<C: CurveConfig<N>, const N: usize> core::fmt::Debug for RecoverableSignature<C, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoverableSignature")
            .field("r", &self.sig.r)
            .field("s", &self.sig.s)
            .field("v", &self.recovery_id)
            .finish()
    }
}

impl<C: CurveConfig<N>, const N: usize> RecoverableSignature<C, N> {
    /// Creates a recoverable signature from a [`Signature`] and [`RecoveryId`].
    #[inline]
    pub const fn new(sig: Signature<C, N>, recovery_id: RecoveryId) -> Self {
        Self { sig, recovery_id }
    }

    /// Returns the inner [`Signature`].
    #[inline]
    pub const fn signature(&self) -> &Signature<C, N> {
        &self.sig
    }

    /// Returns the [`RecoveryId`].
    #[inline]
    pub const fn recovery_id(&self) -> RecoveryId {
        self.recovery_id
    }

    /// Decomposes into `(Signature, RecoveryId)`.
    #[inline]
    pub const fn into_parts(self) -> (Signature<C, N>, RecoveryId) {
        (self.sig, self.recovery_id)
    }

    /// Normalizes into "low S" form, adjusting the recovery ID accordingly. Returns `None` if
    /// already normalized.
    pub fn normalize_s(&self) -> Option<Self> {
        let normalized = self.sig.normalize_s()?;
        Some(Self { sig: normalized, recovery_id: self.recovery_id.flip_y_parity() })
    }

    /// Returns the signature in "low S" form, negating `s` and flipping the recovery ID if
    /// needed. See [`normalize_s`](Self::normalize_s).
    #[inline]
    pub fn normalized_s(self) -> Self {
        self.normalize_s().unwrap_or(self)
    }
}

// --- RecoverableSignature sign/verify/recover requires prime-field base coordinates ---

impl<P: FieldConfig<N>, C: PrimeCurveConfig<N, BaseFieldConfig = P>, const N: usize>
    RecoverableSignature<C, N>
{
    /// Signs a message hash with private key `d` and nonce `k`, producing a recoverable
    /// signature. The returned signature is **not** automatically normalized to low-S. Call
    /// [`normalized_s`](Self::normalized_s) if your protocol requires it.
    ///
    /// # Panics
    ///
    /// Panics if `k` is zero.
    pub fn sign(d: &ScalarField<C, N>, k: &ScalarField<C, N>, hash: &[u8]) -> Option<Self> {
        let (r, s, x, y) = sign_raw::<P, C, N>(d, k, hash)?;

        // x < p < 2n (enforced by base_to_scalar), so one bit suffices for recovery
        let is_x_reduced = x.as_bigint() >= &C::ScalarFieldConfig::MODULUS;
        let is_y_odd = y.as_bigint().is_odd();

        Some(Self { sig: Signature { r, s }, recovery_id: RecoveryId::new(is_y_odd, is_x_reduced) })
    }

    /// Verifies this signature and checks that `pubkey` is the unique public key recoverable from
    /// the signature, recovery ID, and `hash`.
    pub fn verify(&self, pubkey: &AffinePoint<C, N>, hash: &[u8]) -> bool {
        let Some((rx, ry)) = self.sig.reconstruct_r(pubkey, hash).xy() else {
            return false;
        };

        // recovery ID checks: y parity and x reduction must match
        if self.recovery_id.is_y_odd() != ry.as_bigint().is_odd() {
            return false;
        }
        if self.recovery_id.is_x_reduced() != (rx.as_bigint() >= &C::ScalarFieldConfig::MODULUS) {
            return false;
        }

        base_to_scalar::<P, C, N>(rx) == self.sig.r
    }

    /// Recovers the public key from this signature, recovery ID, and message hash.
    pub fn recover(&self, hash: &[u8]) -> Option<AffinePoint<C, N>> {
        let rx = if self.recovery_id.is_x_reduced() {
            let rx = self.sig.r.as_bigint() + &C::ScalarFieldConfig::MODULUS;
            if &rx < self.sig.r.as_bigint() {
                return None;
            }
            Fp::<P, N>::from_bigint(rx)?
        } else if C::ScalarFieldConfig::MODULUS.const_lt(&P::MODULUS) {
            // SAFETY: n < p, so r < n < p is already a valid base field element
            unsafe { Fp::<P, N>::from_bigint_unchecked(self.sig.r.into()) }
        } else {
            Fp::<P, N>::from_bigint(self.sig.r.into())?
        };
        let r_pt = AffinePoint::decompress(rx, self.recovery_id.is_y_odd())?;

        let z = ScalarField::<C, N>::from_be_bytes_mod_order(hash);
        let r_inv = self.sig.r.as_unverified().inverse();
        let u1 = &r_inv * &self.sig.s;
        let mut u2 = &r_inv * &z;
        u2.neg_in_place();

        let g_pt = &AffinePoint::GENERATOR;
        Some(AffinePoint::double_scalar_mul(u1.check_ref(), &r_pt, u2.check_ref(), g_pt))
    }
}

/// `(r, s, R.x, R.y)` from the core signing computation.
type SignRaw<P, C, const N: usize> = (ScalarField<C, N>, ScalarField<C, N>, Fp<P, N>, Fp<P, N>);

/// Core ECDSA signing computation. Returns `(r, s, R.x, R.y)`. Panics if `k` is zero.
fn sign_raw<P: FieldConfig<N>, C: PrimeCurveConfig<N, BaseFieldConfig = P>, const N: usize>(
    d: &ScalarField<C, N>,
    k: &ScalarField<C, N>,
    hash: &[u8],
) -> Option<SignRaw<P, C, N>> {
    assert!(!k.is_zero(), "nonce k must be nonzero");

    // R = [k]G
    let r_pt = &AffinePoint::<C, N>::GENERATOR * k;
    // SAFETY: [k]G is not identity for nonzero k
    let (x, y) = unsafe { r_pt.xy().unwrap_unchecked() };

    // r = R.x mod n
    let r = base_to_scalar::<P, C, N>(x);
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

    Some((r, s, x, y))
}

/// Interprets a base field element as a scalar, reducing mod n.
fn base_to_scalar<
    P: FieldConfig<N>,
    C: PrimeCurveConfig<N, BaseFieldConfig = P>,
    const N: usize,
>(
    x: Fp<P, N>,
) -> ScalarField<C, N> {
    const {
        assert!(
            C::ScalarFieldConfig::MODULUS_BIT_LEN >= P::MODULUS_BIT_LEN,
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

    mod recovery {
        use super::*;

        type RSig = RecoverableSignature<secp256k1::Config, 8>;

        #[test]
        fn recovery_id_basics() {
            let id = RecoveryId::new(false, false);
            assert_eq!(id.to_byte(), 0);
            assert!(!id.is_y_odd());
            assert!(!id.is_x_reduced());

            let id = RecoveryId::new(true, true);
            assert_eq!(id.to_byte(), 3);
            assert!(id.is_y_odd());
            assert!(id.is_x_reduced());

            assert_eq!(RecoveryId::from_byte(2), Some(RecoveryId::new(false, true)));
            assert!(RecoveryId::from_byte(4).is_none());

            // flip_y_parity toggles bit 0
            assert_eq!(RecoveryId::new(false, false).flip_y_parity(), RecoveryId::new(true, false));
            assert_eq!(RecoveryId::new(true, true).flip_y_parity(), RecoveryId::new(false, true));
        }

        #[test]
        fn sign_verify_roundtrip() {
            let d: Fr = fp!("0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
            let pubkey = &Affine::GENERATOR * &d;
            let k: Fr = fp!("0xa6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60");

            let rsig = RSig::sign(&d, &k, HASH).unwrap();

            // standard verify still works via inner signature
            assert!(rsig.signature().verify(&pubkey, HASH));

            // recovery-aware verify accepts the correct pubkey
            assert!(rsig.verify(&pubkey, HASH));
        }

        #[test]
        fn wrong_recovery_id() {
            let d: Fr = fp!("0x1");
            let pubkey = &Affine::GENERATOR * &d;
            let k: Fr = fp!("0x2");

            let rsig = RSig::sign(&d, &k, HASH).unwrap();
            assert!(rsig.verify(&pubkey, HASH));

            // flipping y parity should reject
            let wrong_y = RecoverableSignature::new(
                rsig.signature().clone(),
                rsig.recovery_id().flip_y_parity(),
            );
            assert!(!wrong_y.verify(&pubkey, HASH));

            // flipping x_reduced should reject (for secp256k1, x < n almost always)
            let recid = rsig.recovery_id();
            let wrong_x = RecoverableSignature::new(
                rsig.signature().clone(),
                RecoveryId::new(recid.is_y_odd(), !recid.is_x_reduced()),
            );
            assert!(!wrong_x.verify(&pubkey, HASH));
        }

        #[test]
        fn wrong_pubkey() {
            let d: Fr = fp!("0x1");
            let k: Fr = fp!("0x2");

            let rsig = RSig::sign(&d, &k, HASH).unwrap();
            let wrong_pk = &Affine::GENERATOR * &Fr::from_u32(2);
            assert!(!rsig.verify(&wrong_pk, HASH));
        }

        #[test]
        fn recover_pubkey() {
            let d: Fr = fp!("0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
            let pubkey = &Affine::GENERATOR * &d;
            let k: Fr = fp!("0xa6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60");

            let rsig = RSig::sign(&d, &k, HASH).unwrap();
            let recovered = rsig.recover(HASH).unwrap();
            assert_eq!(recovered, pubkey);
        }

        #[test]
        fn recover_wrong_hash() {
            let d: Fr = fp!("0x1");
            let pubkey = &Affine::GENERATOR * &d;
            let k: Fr = fp!("0x2");

            let rsig = RSig::sign(&d, &k, HASH).unwrap();
            let recovered = rsig.recover(&[0xff]).unwrap();
            assert_ne!(recovered, pubkey);
        }

        #[test]
        fn recover_x_reduced() {
            let x_reduced = RecoveryId::new(false, true);

            // r = 2: smallest r where x = r + n is on secp256k1 (verified offline)
            let sig = Sig::new(Fr::from_u32(2), Fr::ONE).unwrap();
            let rsig = RecoverableSignature::new(sig, x_reduced);
            let pk = rsig.recover(HASH).expect("r + n should be on the curve for r = 2");
            assert!(rsig.signature().verify(&pk, HASH));

            // r = p - n: r + n = p, must be rejected (>= p)
            let sig = Sig::new(fp!("0x14551231950b75fc4402da1722fc9baee"), Fr::ONE).unwrap();
            let rsig = RecoverableSignature::new(sig, x_reduced);
            assert!(rsig.recover(HASH).is_none());
        }
    }
}

#[cfg(test)]
mod wycheproof {
    use super::*;
    use crate::BigInt;
    use ::wycheproof::ecdsa::{TestName, TestSet};
    use sha2::Digest;

    /// Parses a P1363 signature (r || s). Returns `None` if malformed.
    fn parse_sig<C: CurveConfig<N>, const N: usize>(bytes: &[u8]) -> Option<Signature<C, N>> {
        if bytes.len() != 2 * N * 4 {
            return None;
        }
        let (r, s) = bytes.split_at(N * 4);
        let r = Fp::from_bigint(BigInt::from_be_bytes(r))?;
        let s = Fp::from_bigint(BigInt::from_be_bytes(s))?;
        Signature::new(r, s)
    }

    fn run_verify_tests<
        P: FieldConfig<N>,
        C: PrimeCurveConfig<N, BaseFieldConfig = P>,
        D: Digest,
        const N: usize,
    >(
        name: TestName,
    ) {
        let test_set = TestSet::load(name).unwrap();

        for group in &test_set.test_groups {
            let pk_bytes: &[u8] = &group.key.key;

            assert_eq!(pk_bytes[0], 0x04, "expected uncompressed point");
            let x = Fp::from_bigint(BigInt::from_be_bytes(&pk_bytes[1..1 + N * 4])).unwrap();
            let y = Fp::from_bigint(BigInt::from_be_bytes(&pk_bytes[1 + N * 4..])).unwrap();
            let pubkey = AffinePoint::<C, N>::new_in_subgroup(x, y).unwrap();

            for tc in &group.tests {
                let verified = parse_sig::<C, N>(&tc.sig)
                    .is_some_and(|sig| sig.verify(&pubkey, &D::digest(&*tc.msg)));

                let expected = !tc.result.must_fail();
                assert_eq!(verified, expected, "tcId {}: {}", tc.tc_id, tc.comment);
            }
        }
    }

    #[test]
    fn secp256k1_sha256() {
        use crate::curves::secp256k1;
        run_verify_tests::<secp256k1::FqConfig, secp256k1::Config, sha2::Sha256, 8>(
            TestName::EcdsaSecp256k1Sha256P1363,
        );
    }

    #[test]
    fn secp256r1_sha256() {
        use crate::curves::secp256r1;
        run_verify_tests::<secp256r1::FqConfig, secp256r1::Config, sha2::Sha256, 8>(
            TestName::EcdsaSecp256r1Sha256P1363,
        );
    }

    #[test]
    fn secp384r1_sha384() {
        use crate::curves::secp384r1;
        run_verify_tests::<secp384r1::FqConfig, secp384r1::Config, sha2::Sha384, 12>(
            TestName::EcdsaSecp384r1Sha384P1363,
        );
    }
}
