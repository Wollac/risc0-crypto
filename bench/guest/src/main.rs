#![no_main]

extern crate alloc;

use core::hint::black_box;
use risc0_crypto::{
    BigInt, FieldConfig,
    curves::{secp256r1, secp384r1},
    fp,
    modexp::modexp,
};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    // measure logging overhead (empty span)
    env::log("cycle-start: overhead/log");
    env::log("cycle-end: overhead/log");

    bench_ecrecover();
    bench_eip196();
    bench_eip2537();
    bench_eip2537_msm();
    bench_field_ops();
    bench_ec_ops();
    bench_modexp();
}

// -- ecrecover (secp256k1) --
//
// uses the revm-precompile Crypto interface:
//   fn secp256k1_ecrecover(sig: &[u8; 64], recid: u8, msg: &[u8; 32])
//
// the timed region includes all parsing from raw bytes.

/// Generate a valid secp256k1 signature in raw-byte form (not timed).
fn ecrecover_setup() -> ([u8; 64], u8, [u8; 32]) {
    use risc0_crypto::{curves::secp256k1, ecdsa::RecoverableSignature};

    let d: secp256k1::Fr =
        fp!("0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    let k: secp256k1::Fr =
        fp!("0xa6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60");
    let msg: [u8; 32] = [
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
        0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c,
    ];

    let rsig =
        RecoverableSignature::<secp256k1::Config, 8>::sign(&d, &k, &msg).unwrap().normalized_s();

    let mut sig_bytes = [0u8; 64];
    rsig.signature().r().as_bigint().write_be_bytes(&mut sig_bytes[..32]);
    rsig.signature().s().as_bigint().write_be_bytes(&mut sig_bytes[32..]);
    let recid = rsig.recovery_id().to_byte();

    (sig_bytes, recid, msg)
}

/// secp256k1 ecrecover via risc0-crypto (revm-precompile interface).
fn ecrecover_risc0(sig: &[u8; 64], recid: u8, msg: &[u8; 32]) -> Option<[u8; 64]> {
    use risc0_crypto::{
        curves::secp256k1,
        ecdsa::{RecoverableSignature, RecoveryId, Signature},
    };

    let r = secp256k1::Fr::from_bigint(BigInt::from_be_bytes(&sig[..32]))?;
    let s = secp256k1::Fr::from_bigint(BigInt::from_be_bytes(&sig[32..]))?;
    let inner = Signature::<secp256k1::Config, 8>::new(r, s)?;
    let recovery_id = RecoveryId::from_byte(recid)?;
    let rsig = RecoverableSignature::new(inner, recovery_id);

    let pubkey = rsig.recover(msg as &[u8])?;
    let (x, y) = pubkey.xy()?;

    let mut result = [0u8; 64];
    x.as_bigint().write_be_bytes(&mut result[..32]);
    y.as_bigint().write_be_bytes(&mut result[32..]);
    Some(result)
}

fn bench_ecrecover() {
    let (sig, recid, msg) = ecrecover_setup();

    env::log("cycle-start: ecrecover");
    let r = ecrecover_risc0(black_box(&sig), black_box(recid), black_box(&msg));
    black_box(&r);
    env::log("cycle-end: ecrecover");

    assert!(r.is_some(), "ecrecover failed");
}

// -- EIP-196 (BN254 G1 add & mul) --
//
// uses the revm-precompile Crypto interface:
//   fn bn254_g1_add(p1: &[u8], p2: &[u8]) -> Option<[u8; 64]>
//   fn bn254_g1_mul(point: &[u8], scalar: &[u8]) -> Option<[u8; 64]>
//
// the timed region includes all parsing from raw bytes.

/// Generate test inputs for EIP-196 benchmarks (not timed).
fn eip196_setup() -> ([u8; 64], [u8; 64], [u8; 32]) {
    use risc0_crypto::curves::bn254;

    let g = bn254::Affine::GENERATOR;
    let scalar: bn254::Fr =
        fp!("0x0c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f672");
    let p2 = &g * &scalar;

    let mut p1_bytes = [0u8; 64];
    let (gx, gy) = g.xy().unwrap();
    gx.as_bigint().write_be_bytes(&mut p1_bytes[..32]);
    gy.as_bigint().write_be_bytes(&mut p1_bytes[32..]);

    let mut p2_bytes = [0u8; 64];
    let (p2x, p2y) = p2.xy().unwrap();
    p2x.as_bigint().write_be_bytes(&mut p2_bytes[..32]);
    p2y.as_bigint().write_be_bytes(&mut p2_bytes[32..]);

    let mut scalar_bytes = [0u8; 32];
    scalar.as_bigint().write_be_bytes(&mut scalar_bytes);

    (p1_bytes, p2_bytes, scalar_bytes)
}

/// BN254 G1 point addition via risc0-crypto (revm-precompile interface).
fn bn254_g1_add(p1: &[u8], p2: &[u8]) -> Option<[u8; 64]> {
    use risc0_crypto::curves::bn254;

    let read = |data: &[u8]| -> Option<bn254::Affine> {
        let x = bn254::Fq::from_bigint(BigInt::from_be_bytes(&data[..32]))?;
        let y = bn254::Fq::from_bigint(BigInt::from_be_bytes(&data[32..64]))?;
        if x.is_zero() && y.is_zero() {
            Some(bn254::Affine::IDENTITY)
        } else {
            bn254::Affine::new(x, y)
        }
    };

    let p1 = read(p1)?;
    let p2 = read(p2)?;
    let sum = &p1 + &p2;

    let mut result = [0u8; 64];
    if let Some((x, y)) = sum.xy() {
        x.as_bigint().write_be_bytes(&mut result[..32]);
        y.as_bigint().write_be_bytes(&mut result[32..]);
    }
    Some(result)
}

/// BN254 G1 scalar multiplication via risc0-crypto (revm-precompile interface).
fn bn254_g1_mul(point: &[u8], scalar: &[u8]) -> Option<[u8; 64]> {
    use risc0_crypto::curves::bn254;

    let x = bn254::Fq::from_bigint(BigInt::from_be_bytes(&point[..32]))?;
    let y = bn254::Fq::from_bigint(BigInt::from_be_bytes(&point[32..64]))?;
    let p = if x.is_zero() && y.is_zero() {
        bn254::Affine::IDENTITY
    } else {
        bn254::Affine::new(x, y)?
    };

    // EVM scalar is a raw 256-bit uint, may be >= group order
    let s = bn254::Fr::reduce_from_bigint(BigInt::from_be_bytes(scalar));
    let product = &p * &s;

    let mut result = [0u8; 64];
    if let Some((x, y)) = product.xy() {
        x.as_bigint().write_be_bytes(&mut result[..32]);
        y.as_bigint().write_be_bytes(&mut result[32..]);
    }
    Some(result)
}

fn bench_eip196() {
    let (p1, p2, scalar) = eip196_setup();

    env::log("cycle-start: eip196/add");
    let r = bn254_g1_add(black_box(&p1), black_box(&p2));
    black_box(&r);
    env::log("cycle-end: eip196/add");
    assert!(r.is_some(), "eip196 add failed");

    env::log("cycle-start: eip196/mul");
    let r = bn254_g1_mul(black_box(&p1), black_box(&scalar));
    black_box(&r);
    env::log("cycle-end: eip196/mul");
    assert!(r.is_some(), "eip196 mul failed");
}

// -- EIP-2537 (BLS12-381 G1 add & MSM) --
//
// uses the revm-precompile Crypto interface:
//   fn bls12_381_g1_add(a: G1Point, b: G1Point) -> [u8; 96]
//   fn bls12_381_g1_msm(pairs: &[(G1Point, [u8; 32])]) -> [u8; 96]
//
// the timed region includes all parsing from raw bytes.

const FP_LENGTH: usize = 48;
type G1Point = ([u8; FP_LENGTH], [u8; FP_LENGTH]);
const SCALAR_LENGTH: usize = 32;
type G1PointScalar = (G1Point, [u8; SCALAR_LENGTH]);

/// Generate test inputs for EIP-2537 benchmarks (not timed).
fn eip2537_setup() -> (G1Point, G1Point) {
    use risc0_crypto::curves::bls12_381;

    let g = bls12_381::Affine::GENERATOR;
    let scalar: bls12_381::Fr =
        fp!("0x0c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f672");
    let p2 = &g * &scalar;

    let encode = |p: &bls12_381::Affine| -> G1Point {
        let (x, y) = p.xy().unwrap();
        let mut x_bytes = [0u8; FP_LENGTH];
        let mut y_bytes = [0u8; FP_LENGTH];
        x.as_bigint().write_be_bytes(&mut x_bytes);
        y.as_bigint().write_be_bytes(&mut y_bytes);
        (x_bytes, y_bytes)
    };

    (encode(&g), encode(&p2))
}

/// BLS12-381 G1 point addition via risc0-crypto (revm-precompile interface).
fn bls12_381_g1_add(a: G1Point, b: G1Point) -> Option<[u8; 96]> {
    use risc0_crypto::curves::bls12_381;

    let read = |point: &G1Point| -> Option<bls12_381::Affine> {
        let x = bls12_381::Fq::from_bigint(BigInt::from_be_bytes(&point.0))?;
        let y = bls12_381::Fq::from_bigint(BigInt::from_be_bytes(&point.1))?;
        if x.is_zero() && y.is_zero() {
            Some(bls12_381::Affine::IDENTITY)
        } else {
            bls12_381::Affine::new(x, y)
        }
    };

    let p1 = read(&a)?;
    let p2 = read(&b)?;
    let sum = &p1 + &p2;

    let mut result = [0u8; 96];
    if let Some((x, y)) = sum.xy() {
        x.as_bigint().write_be_bytes(&mut result[..FP_LENGTH]);
        y.as_bigint().write_be_bytes(&mut result[FP_LENGTH..]);
    }
    Some(result)
}

fn bench_eip2537() {
    let (a, b) = eip2537_setup();

    env::log("cycle-start: eip2537/add");
    let r = bls12_381_g1_add(black_box(a), black_box(b));
    black_box(&r);
    env::log("cycle-end: eip2537/add");

    assert!(r.is_some(), "eip2537 add failed");
}

/// Generate 128 distinct (point, scalar) pairs for MSM benchmarks (not timed).
fn eip2537_msm_setup() -> alloc::vec::Vec<G1PointScalar> {
    use alloc::vec::Vec;
    use risc0_crypto::curves::bls12_381;

    let g = bls12_381::Affine::GENERATOR;

    let encode_point = |p: &bls12_381::Affine| -> G1Point {
        let (x, y) = p.xy().unwrap();
        let mut xb = [0u8; FP_LENGTH];
        let mut yb = [0u8; FP_LENGTH];
        x.as_bigint().write_be_bytes(&mut xb);
        y.as_bigint().write_be_bytes(&mut yb);
        (xb, yb)
    };

    // deterministic full-size scalars (all < 2^254 < BLS12-381 scalar order)
    let make_scalar = |i: usize| -> [u8; SCALAR_LENGTH] {
        let mut s = [0u8; SCALAR_LENGTH];
        for j in 0..SCALAR_LENGTH {
            s[j] =
                (i.wrapping_add(1).wrapping_mul(j + 1).wrapping_mul(0x9e).wrapping_add(0x37)) as u8;
        }
        s[0] &= 0x3f; // clear top 2 bits -> value < 2^254
        s
    };

    // 128 distinct points: G, [2]G, [4]G, ... via repeated doubling
    let mut p = g;
    let mut result = Vec::with_capacity(128);
    for i in 0..128 {
        result.push((encode_point(&p), make_scalar(i)));
        p = p.double();
    }
    result
}

/// Parse a G1Point from raw bytes into a BLS12-381 affine point (with subgroup
/// check).
fn read_g1(point: &G1Point) -> Option<risc0_crypto::curves::bls12_381::Affine> {
    use risc0_crypto::curves::bls12_381;
    let x = bls12_381::Fq::from_bigint(BigInt::from_be_bytes(&point.0))?;
    let y = bls12_381::Fq::from_bigint(BigInt::from_be_bytes(&point.1))?;
    if x.is_zero() && y.is_zero() {
        Some(bls12_381::Affine::IDENTITY)
    } else {
        bls12_381::Affine::new_in_subgroup(x, y)
    }
}

/// Parse a 32-byte big-endian EIP scalar into a BLS12-381 scalar field element.
fn read_scalar(scalar: &[u8; SCALAR_LENGTH]) -> risc0_crypto::curves::bls12_381::Fr {
    use risc0_crypto::curves::bls12_381;
    bls12_381::Fr::reduce_from_bigint(BigInt::from_be_bytes(scalar))
}

/// Encode a BLS12-381 affine point as 96 big-endian bytes.
fn encode_g1(p: &risc0_crypto::curves::bls12_381::Affine) -> [u8; 96] {
    let mut result = [0u8; 96];
    if let Some((x, y)) = p.xy() {
        x.as_bigint().write_be_bytes(&mut result[..FP_LENGTH]);
        y.as_bigint().write_be_bytes(&mut result[FP_LENGTH..]);
    }
    result
}

/// BLS12-381 G1 MSM via risc0-crypto.
/// k=1: direct scalar mul. k>1: double_scalar_mul (Shamir's trick) on
/// chunks of 2, with a trailing single scalar mul for odd k.
fn bls12_381_g1_msm(pairs: &[G1PointScalar]) -> Option<[u8; 96]> {
    use risc0_crypto::curves::bls12_381;

    if pairs.len() == 1 {
        // k=1: direct scalar mul, no accumulator overhead
        let p = read_g1(&pairs[0].0)?;
        let s = read_scalar(&pairs[0].1);
        return Some(encode_g1(&(&p * &s)));
    }

    // k>1: process pairs via double_scalar_mul (Shamir's trick) - saves ~n
    // doublings per pair compared to two independent scalar muls.
    let mut acc = bls12_381::Affine::IDENTITY;
    for chunk in pairs.chunks_exact(2) {
        let p0 = read_g1(&chunk[0].0)?;
        let s0 = read_scalar(&chunk[0].1);
        let p1 = read_g1(&chunk[1].0)?;
        let s1 = read_scalar(&chunk[1].1);
        acc = &acc + &bls12_381::Affine::double_scalar_mul(&s0, &p0, &s1, &p1);
    }
    Some(encode_g1(&acc))
}

fn bench_eip2537_msm() {
    let pairs = eip2537_msm_setup();

    for &k in &[1, 128] {
        env::log(&format!("cycle-start: eip2537/msm_{k}"));
        let r = bls12_381_g1_msm(black_box(&pairs[..k]));
        black_box(&r);
        env::log(&format!("cycle-end: eip2537/msm_{k}"));

        assert!(r.is_some(), "eip2537 msm k={k} failed");
    }
}

// -- field benchmarks --

const BENCH_ITERS: u32 = 10;

macro_rules! bench_field {
    ($name:expr, $Fq:ty, $val:expr) => {{
        let v: $Fq = $val;

        env::log(&format!("cycle-start: {}/add*{}", $name, BENCH_ITERS));
        for _ in 0..BENCH_ITERS {
            let _ = black_box(black_box(&v) + black_box(&v));
        }
        env::log(&format!("cycle-end: {}/add*{}", $name, BENCH_ITERS));

        env::log(&format!("cycle-start: {}/mul*{}", $name, BENCH_ITERS));
        for _ in 0..BENCH_ITERS {
            let _ = black_box(black_box(&v) * black_box(&v));
        }
        env::log(&format!("cycle-end: {}/mul*{}", $name, BENCH_ITERS));

        env::log(&format!("cycle-start: {}/inverse*{}", $name, BENCH_ITERS));
        for _ in 0..BENCH_ITERS {
            let _ = black_box(black_box(&v).inverse());
        }
        env::log(&format!("cycle-end: {}/inverse*{}", $name, BENCH_ITERS));
    }};
}

fn bench_field_ops() {
    // 256-bit
    bench_field!(
        "field/secp256r1",
        secp256r1::Fq,
        fp!("0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
    );
    // 384-bit
    bench_field!(
        "field/secp384r1",
        secp384r1::Fq,
        fp!("0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721deadbeef")
    );
}

// -- EC benchmarks --
//
// two representative curves:
// - secp256r1: 256-bit (NIST P-256)
// - secp384r1: 384-bit (NIST P-384)

macro_rules! bench_ec {
    ($name:expr, $Affine:ty, $Fr:ty, $scalar:expr) => {{
        let g = <$Affine>::GENERATOR;
        let scalar: $Fr = $scalar;

        env::log(&format!("cycle-start: {}/is_on_curve*{}", $name, BENCH_ITERS));
        for _ in 0..BENCH_ITERS {
            let _ = black_box(black_box(&g).is_on_curve());
        }
        env::log(&format!("cycle-end: {}/is_on_curve*{}", $name, BENCH_ITERS));

        env::log(&format!("cycle-start: {}/point_double*{}", $name, BENCH_ITERS));
        for _ in 0..BENCH_ITERS {
            let _ = black_box(black_box(&g).double());
        }
        env::log(&format!("cycle-end: {}/point_double*{}", $name, BENCH_ITERS));

        let p2 = <$Affine>::GENERATOR.double();
        env::log(&format!("cycle-start: {}/point_add*{}", $name, BENCH_ITERS));
        for _ in 0..BENCH_ITERS {
            let _ = black_box(black_box(&g) + black_box(&p2));
        }
        env::log(&format!("cycle-end: {}/point_add*{}", $name, BENCH_ITERS));

        env::log(&format!("cycle-start: {}/scalar_mul", $name));
        let _ = black_box(black_box(&g) * black_box(&scalar));
        env::log(&format!("cycle-end: {}/scalar_mul", $name));
    }};
}

macro_rules! bench_ecdsa {
    ($name:expr, $Config:ty, $Fr:ty, $Affine:ty, $N:expr, $d:expr, $k:expr) => {{
        let d: $Fr = $d;
        let k: $Fr = $k;
        let hash: &[u8] = &[0xde, 0xad, 0xbe, 0xef];
        // precompute pubkey (not timed)
        let pubkey = &<$Affine>::GENERATOR * &d;

        env::log(&format!("cycle-start: {}/ecdsa_sign", $name));
        let sig = risc0_crypto::ecdsa::Signature::<$Config, $N>::sign(
            black_box(&d),
            black_box(&k),
            black_box(hash),
        )
        .unwrap();
        black_box(&sig);
        env::log(&format!("cycle-end: {}/ecdsa_sign", $name));

        let sig =
            risc0_crypto::ecdsa::RecoverableSignature::<$Config, $N>::sign(&d, &k, hash).unwrap();

        env::log(&format!("cycle-start: {}/ecdsa_verify", $name));
        let ok = sig.verify(black_box(&pubkey), black_box(hash));
        black_box(ok);
        env::log(&format!("cycle-end: {}/ecdsa_verify", $name));
        assert!(ok, "ecdsa_verify failed");

        env::log(&format!("cycle-start: {}/ecdsa_recover", $name));
        let recovered = sig.recover(black_box(hash)).unwrap();
        black_box(&recovered);
        env::log(&format!("cycle-end: {}/ecdsa_recover", $name));
    }};
}

fn bench_ec_ops() {
    // 256-bit (NIST P-256)
    bench_ec!(
        "ec/secp256r1",
        secp256r1::Affine,
        secp256r1::Fr,
        fp!("0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
    );
    bench_ecdsa!(
        "ec/secp256r1",
        secp256r1::Config,
        secp256r1::Fr,
        secp256r1::Affine,
        8,
        fp!("0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"),
        fp!("0xa6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60")
    );

    // 384-bit (NIST P-384)
    bench_ec!(
        "ec/secp384r1",
        secp384r1::Affine,
        secp384r1::Fr,
        fp!("0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721deadbeef")
    );
    bench_ecdsa!(
        "ec/secp384r1",
        secp384r1::Config,
        secp384r1::Fr,
        secp384r1::Affine,
        12,
        fp!("0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721deadbeef"),
        fp!("0xa6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60cafebabe")
    );
}

// -- modexp benchmarks --

fn bench_modexp() {
    // exponents with every other bit set, full width
    let exp_256: BigInt<8> = BigInt([0xaaaaaaaa; 8]);
    let exp_384: BigInt<12> = BigInt([0xaaaaaaaa; 12]);

    // 256-bit: secp256r1 field prime
    env::log("cycle-start: modexp/256bit");
    let _ = black_box(modexp(&BigInt::from_u32(2), &exp_256, &secp256r1::FqConfig::MODULUS));
    env::log("cycle-end: modexp/256bit");

    // 384-bit: secp384r1 field prime
    env::log("cycle-start: modexp/384bit");
    let _ = black_box(modexp(&BigInt::from_u32(2), &exp_384, &secp384r1::FqConfig::MODULUS));
    env::log("cycle-end: modexp/384bit");

    // 4096-bit with RSA-like parameters
    // modulus: two 0xff..ff halves with distinct low limbs (simulates a real RSA modulus)
    let mod_4096: BigInt<128> = BigInt([0xffffffff; 128]);
    // base: small message representative
    let base_4096: BigInt<128> = BigInt::from_u32(0xdeadbeef);

    // RSA verify: public exponent e = 65537 (17 bits - very cheap)
    let exp_e: BigInt<128> = BigInt::from_u32(65537);
    env::log("cycle-start: modexp/4096bit_e65537");
    let _ = black_box(modexp(&base_4096, &exp_e, &mod_4096));
    env::log("cycle-end: modexp/4096bit_e65537");

    // RSA sign: full 4096-bit private exponent d (realistic density)
    let exp_4096: BigInt<128> = BigInt([0xaaaaaaaa; 128]);
    env::log("cycle-start: modexp/4096bit_full");
    let _ = black_box(modexp(&base_4096, &exp_4096, &mod_4096));
    env::log("cycle-end: modexp/4096bit_full");
}
