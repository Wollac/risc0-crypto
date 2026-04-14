#![no_main]

extern crate alloc;

use core::hint::black_box;
use hex_literal::hex;
use risc0_crypto::{
    BigInt, FieldConfig,
    curves::{bls12_381, bn254, secp256k1, secp256r1, secp384r1},
    ecdsa::{RecoverableSignature, RecoveryId, Signature},
    fp,
    modexp::modexp,
};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

/// Benchmark a block, logging cycle-start/end markers around it. Formatting (if any) happens before
/// the timed region so it doesn't consume measured cycles.
macro_rules! bench {
    ($fmt:literal, $($args:expr),+ ; $body:expr) => {{
        let __start = format!(concat!("cycle-start: ", $fmt), $($args),+);
        let __end = format!(concat!("cycle-end: ", $fmt), $($args),+);
        env::log(&__start);
        let _ = black_box($body);
        env::log(&__end);
    }};
    ($label:literal ; $body:expr) => {{
        env::log(concat!("cycle-start: ", $label));
        let _ = black_box($body);
        env::log(concat!("cycle-end: ", $label));
    }};
}

fn main() {
    bench_ecrecover();
    bench_eip196();
    bench_eip2537();
    bench_eip2537_msm();
    bench_field_ops();
    bench_ec_ops();
    bench_modexp();
}

// -- ecrecover (secp256k1) --

fn ecrecover(sig: &[u8; 64], recid: u8, msg: &[u8; 32]) -> Option<[u8; 64]> {
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
    // inputs from mainnet tx 0x1b776310498b6698eaa2f10fab95b99b54341e02ad9e3dba1bf14491e9adf6fb
    // r || s
    let sig = hex!(
        "03fadfb3d6408f98b915088019536557e77a7a3359ecff73c967ffcee52cdb9922e4a1bd0a7730907fa75e196d57b46ad037aba53b7b968ba11e046788e22a98"
    );
    let recid: u8 = 0; // v = 27
    let msg = hex!("cdefda47615b9f7767dc9f08d679f563539428ead76a4f5004bef34296ca3a75");

    bench!("ecrecover"; {
        ecrecover(&sig, recid, &msg)
    });
}

// -- EIP-196 (BN254 G1 add & mul) --

fn decode_bn254_g1(data: &[u8]) -> Option<bn254::Affine> {
    let x = bn254::Fq::from_bigint(BigInt::from_be_bytes(&data[..32]))?;
    let y = bn254::Fq::from_bigint(BigInt::from_be_bytes(&data[32..64]))?;
    if x.is_zero() && y.is_zero() {
        Some(bn254::Affine::IDENTITY)
    } else {
        bn254::Affine::new(x, y)
    }
}

fn encode_bn254_g1(p: &bn254::Affine) -> [u8; 64] {
    let mut result = [0u8; 64];
    if let Some((x, y)) = p.xy() {
        x.as_bigint().write_be_bytes(&mut result[..32]);
        y.as_bigint().write_be_bytes(&mut result[32..]);
    }
    result
}

// revm-precompile interface
fn bn254_g1_add(p1: &[u8], p2: &[u8]) -> Option<[u8; 64]> {
    let p1 = decode_bn254_g1(p1)?;
    let p2 = decode_bn254_g1(p2)?;
    Some(encode_bn254_g1(&(&p1 + &p2)))
}

// revm-precompile interface
fn bn254_g1_mul(point: &[u8], scalar: &[u8]) -> Option<[u8; 64]> {
    let p = decode_bn254_g1(point)?;
    // EVM scalar is a raw 256-bit uint, may be >= group order
    let s = bn254::Fr::reduce_from_bigint(BigInt::from_be_bytes(scalar));
    Some(encode_bn254_g1(&(&p * &s)))
}

fn bench_eip196() {
    // inputs from mainnet tx 0x45dbdb9cc9f1b0de5e55d1391dc629ec882a03b01984a3773c190d5d5ca9c1b1
    // two points from an ecAdd (0x06) precompile call
    let p1 = hex!(
        "23e07a143bca640ec21b084028d06c7ef874a4da264a9eac0676f506c679b1c52c078a1a2fffc75717398847de7cc8328965b889d6eafa1d716fc7ccb80a1d2b"
    );
    let p2 = hex!(
        "11ef95e4c08f2970205824309f2bc3ebbc59214cb415a3041f00fb9d761caa732d6b61791aede93ecb204d931a67603f321408639f6d00fcea2a3d92e7492262"
    );
    // scalar from an ecMul (0x07) precompile call in the same tx
    let scalar = hex!("22a7782a8db95c39edde875fbfcf6b3c469bec1096dc379e944508eec74d74ad");

    bench!("eip196/add"; {
        bn254_g1_add(&p1, &p2)
    });

    bench!("eip196/mul"; {
        bn254_g1_mul(&p1, &scalar)
    });
}

// -- EIP-2537 (BLS12-381 G1 add & MSM) --

const BLS_FP_LENGTH: usize = 48;
type BlsG1Point = ([u8; BLS_FP_LENGTH], [u8; BLS_FP_LENGTH]);
const BLS_SCALAR_LENGTH: usize = 32;
type BlsG1PointScalar = (BlsG1Point, [u8; BLS_SCALAR_LENGTH]);

fn decode_bls12381_g1(point: &BlsG1Point) -> Option<bls12_381::Affine> {
    let x = bls12_381::Fq::from_bigint(BigInt::from_be_bytes(&point.0))?;
    let y = bls12_381::Fq::from_bigint(BigInt::from_be_bytes(&point.1))?;
    if x.is_zero() && y.is_zero() {
        Some(bls12_381::Affine::IDENTITY)
    } else {
        bls12_381::Affine::new(x, y)
    }
}

fn encode_bls12381_g1(p: &bls12_381::Affine) -> [u8; 96] {
    let mut result = [0u8; 96];
    if let Some((x, y)) = p.xy() {
        x.as_bigint().write_be_bytes(&mut result[..BLS_FP_LENGTH]);
        y.as_bigint().write_be_bytes(&mut result[BLS_FP_LENGTH..]);
    }
    result
}

// revm-precompile interface
fn bls12_381_g1_add(a: BlsG1Point, b: BlsG1Point) -> Option<[u8; 96]> {
    let p1 = decode_bls12381_g1(&a)?;
    let p2 = decode_bls12381_g1(&b)?;
    Some(encode_bls12381_g1(&(&p1 + &p2)))
}

fn bench_eip2537() {
    // inputs from mainnet tx 0x815155fbfe4c002377c95a9073c89bffb8413edebc2413a25e5e7b82a6da00b2
    let a: BlsG1Point = (
        hex!(
            "136f564658b7f26baf272ea4e25462a7a4ac9d17d83c4eda81aa47374d68d227930a22195526bd80ee456354a3e1a122"
        ),
        hex!(
            "073f227ca363b58cba59c442aca3806cff2b8c5c7182981505544cc451490697a71d796aa7face0ec848b85254ffdf0d"
        ),
    );
    let b: BlsG1Point = (
        hex!(
            "0115ed13b5630de15cc5686ef7dfe5e90538100ce34b0f46f42f0d6b85b0523bb9f383f38e377aeb5d5cc43808063a15"
        ),
        hex!(
            "03815f96af9e495af16d0e9f8292b72e2d1f9fdd50116342f1853da67317cce7dc1a3b46ab46678c1216896cbe145598"
        ),
    );

    bench!("eip2537/add"; {
        bls12_381_g1_add(a, b)
    });
}

fn eip2537_msm_setup() -> alloc::vec::Vec<BlsG1PointScalar> {
    // base pair from mainnet tx 0x815155fbfe4c002377c95a9073c89bffb8413edebc2413a25e5e7b82a6da00b2
    let point: BlsG1Point = (
        hex!(
            "1186b2f2b6871713b10bc24ef04a9a397e084b3358f7f1404f0a4ee1acc6d254997032f77fd77593fab7c896b7cfce1e"
        ),
        hex!(
            "02b36b71d4948be739d14bb0e8f4a887e2dfa30cd1fca5558bfe26343dc755a0a52ef6115b9aef97d71b047ed5d830c8"
        ),
    );
    let scalar = hex!("11e28d141ff691ea370445925e59f2e1b8fa1217b90f7c55bbaf96d1852451d4");

    // remaining 127 pairs derived by varying the low byte of the scalar
    (0..128)
        .map(|i: u8| {
            let mut s = scalar;
            s[BLS_SCALAR_LENGTH - 1] = i;
            (point, s)
        })
        .collect()
}

// k=1: direct scalar mul. k>1: double_scalar_mul (Shamir's trick) on
// chunks of 2, with a trailing single scalar mul for odd k.
fn bls12_381_g1_msm(pairs: &[BlsG1PointScalar]) -> Option<[u8; 96]> {
    let read_point =
        |p: &BlsG1Point| decode_bls12381_g1(p).filter(|p| p.is_in_correct_subgroup());
    let read_scalar = |s: &[u8; BLS_SCALAR_LENGTH]| {
        bls12_381::Fr::reduce_from_bigint(BigInt::from_be_bytes(s))
    };

    if pairs.len() == 1 {
        let p = read_point(&pairs[0].0)?;
        let s = read_scalar(&pairs[0].1);
        return Some(encode_bls12381_g1(&(&p * &s)));
    }

    let mut acc = bls12_381::Affine::IDENTITY;
    let chunks = pairs.chunks_exact(2);
    let remainder = chunks.remainder();
    for chunk in chunks {
        let p0 = read_point(&chunk[0].0)?;
        let s0 = read_scalar(&chunk[0].1);
        let p1 = read_point(&chunk[1].0)?;
        let s1 = read_scalar(&chunk[1].1);
        acc = &acc + &bls12_381::Affine::double_scalar_mul(&s0, &p0, &s1, &p1);
    }
    if let Some(remainder) = remainder.first() {
        let p = read_point(&remainder.0)?;
        let s = read_scalar(&remainder.1);
        acc = &acc + &(&p * &s);
    }

    Some(encode_bls12381_g1(&acc))
}

fn bench_eip2537_msm() {
    let pairs = eip2537_msm_setup();

    for &k in &[1, 128] {
        bench!("eip2537/msm_{}", k; {
            bls12_381_g1_msm(&pairs[..k])
        });
    }
}

// -- field benchmarks --

const BENCH_ITERS: u32 = 10;

macro_rules! bench_field {
    ($name:expr, $Fq:ty, $val:expr) => {{
        let v: $Fq = $val;

        bench!("{}/add*{}", $name, BENCH_ITERS; {
            for _ in 0..BENCH_ITERS {
                let _ = black_box(black_box(&v) + black_box(&v));
            }
        });

        bench!("{}/mul*{}", $name, BENCH_ITERS; {
            for _ in 0..BENCH_ITERS {
                let _ = black_box(black_box(&v) * black_box(&v));
            }
        });

        bench!("{}/inverse*{}", $name, BENCH_ITERS; {
            for _ in 0..BENCH_ITERS {
                let _ = black_box(black_box(&v).inverse());
            }
        });
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

macro_rules! bench_ec {
    ($name:expr, $Affine:ty, $Fr:ty, $scalar:expr) => {{
        let g = <$Affine>::GENERATOR;
        let scalar: $Fr = $scalar;

        bench!("{}/is_on_curve*{}", $name, BENCH_ITERS; {
            for _ in 0..BENCH_ITERS {
                let _ = black_box(black_box(&g).is_on_curve());
            }
        });

        let p2 = <$Affine>::GENERATOR.double();
        bench!("{}/point_add*{}", $name, BENCH_ITERS; {
            for _ in 0..BENCH_ITERS {
                let _ = black_box(black_box(&g) + black_box(&p2));
            }
        });

        bench!("{}/scalar_mul", $name; {
            &g * &scalar
        });
    }};
}

macro_rules! bench_ecdsa {
    ($name:expr, $Config:ty, $Fr:ty, $Affine:ty, $N:expr, $d:expr, $k:expr) => {{
        let d: $Fr = $d;
        let k: $Fr = $k;
        let hash: &[u8] = &[0xde, 0xad, 0xbe, 0xef];
        // precompute pubkey (not timed)
        let pubkey = &<$Affine>::GENERATOR * &d;

        bench!("{}/ecdsa_sign", $name; {
            Signature::<$Config, $N>::sign(&d, &k, hash).unwrap()
        });

        let sig =
            RecoverableSignature::<$Config, $N>::sign(&d, &k, hash).unwrap();

        bench!("{}/ecdsa_verify", $name; {
            sig.verify(&pubkey, hash)
        });

        bench!("{}/ecdsa_recover", $name; {
            sig.recover(hash).unwrap()
        });
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
    // exponents with every other bit set, full width for 256/384-bit
    let exp_256 = BigInt([0xaaaaaaaa; 8]);
    let exp_384 = BigInt([0xaaaaaaaa; 12]);

    // 256-bit: secp256r1 field prime
    bench!("modexp/256bit"; {
        modexp(&BigInt::from_u32(2), &exp_256, &secp256r1::FqConfig::MODULUS)
    });
    // 384-bit: secp384r1 field prime
    bench!("modexp/384bit"; {
        modexp(&BigInt::from_u32(2), &exp_384, &secp384r1::FqConfig::MODULUS)
    });

    // RSA-4096 verify from mainnet tx 0x956bcca6c59705ea68bdfbf4aadebbd2cd213fd550c0b28ef711337e18a3faf6
    let base_4096 = BigInt::<128>::from_be_bytes(&hex!(
        "8d9989972d6d33ce5e888239b53cf7d7c636099b1faa13153463f01cc8c2cbd89023da0fd78f479eaac426e0a52595708e02993291740696105418b6e248660d39241aea4d04dca609837b0959342d00739a55c52f6b377ae20cf37cff406512f07d94ea3708d3cb5be7165fe5c98021e6645e245767d27e57dbd714449f3c315ede856a9f6007f3aece778ede5e98e65d84b8ed4f108eac57b6f2274cf06ce5ce07c3423f8b63dee09b3dcef9a715783b0bc94a84c600a402aa08754ac4927eda580aa17387071f567e34a4dcb558b4d54db0f6d908a372960becface22fca03a8464c11226c003f2361261300bb5f4e4aff998c488d9866beb7879e10ea7aebb02018f8c16976c356ab0fbf29b1967d9b55571b988744a09795c97bb6b5f030401da10d92f4e39a667b27fd07b55f7ea85a7703e7bbee24a0b5d82f5ad03287bbed3bf5ae87c31aee39ec9f708fad179c758260d58fa4ff8ed6a3a843a21eec06aaa1c6c3f36797af8f848b08072536fd8fc935f1c33b74cd3a64dfd799a071ef53cd3793a077a473067e0dd2c301a664480ce0689f62c1a7bf3fd62dc11a8c80c2ec49f9fb72333a48dbaaf4d66be1f45cfdd5ff6bd2536aa7975f0e1b12b3965b12ed931f4703074820d3f87f4652b525401bbb8bd4257dbc07b58bd9de9ff5042f03c4a91eec761e7d53ffb95c75a8d3e327b0abb5f268959602b4027fe"
    ));
    let mod_4096 = BigInt::<128>::from_be_bytes(&hex!(
        "be82ed99849edfaebd403ab2acf6f4ec93e8070f0603c20210ac7601ccee90de611e15d81befd561149a5673bc8ff5982be2d07d92d8737d54b45b90f0f270e701ce6f1d5036f8838accfbf59a6d34539107914ebca64572524ad5443c778a951b8c5c4c8dd8d96ef7b408b97aa7c0ecfed1a1ded4b376197d952968fee2a6d2dd97579e44b971289bba4ab52a3c1964e16f3ff3c304930821a9bca3ee7ed229ea8f335550cce599e6d6e0b510494639d385eb0c05bb1abdfca6f232f5ac08762f12fab004aa7a663a61974dfb0c2da5f7a50b3114ced5bd6af54edee131a9807cd45cc87c589dd48f93aaf2d1579a5dc2dca7a2efc76be44eb879caf4898940c401d51814dd2ed394e0d901f30d1f1970e85804985759f862f75f8de13fcab2ba9e3f25f8b5b3411f466bbe14a611c1abe961ee9a76f23662cd3382d6e6327cec5b353e06eb1f4ea20734fac638d2e6bfcd80ba53c5eeccdb1c029e9d4d0e83611217da03501ef01417e4b4ae131193b51f25790fc0140fc74a17a9f95098e4724134d82f0a23829e5897877968a284acae4066e342b99c4a44611d140a9d2f8cb79d21d379996fc6088d76f69572042ba3405393e85f363d5cde71c6d230a8e9700d48c8801b402520b312674259bc1e9a53e065034aaf1421c71db360149f84977f7a650d1bdd2c8de1d5acbcb907f4212358d00db18aa75121ddffd32b31"
    ));
    let exp_e = BigInt::<1>::from_u32(65537);
    bench!("modexp/4096bit_e65537"; {
        modexp(&base_4096, &exp_e, &mod_4096)
    });
}
