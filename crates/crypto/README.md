# risc0-crypto

**This crate only builds and links for `riscv32im-risc0-zkvm-elf`.** Use it from
[RISC Zero](https://risczero.com/) guest code only - linking from a host binary fails by design,
since the primitives call `risc0-bigint2` syscalls that only the R0VM guest runtime defines.

> ⚠️ **This crate has not been independently audited.**

Cryptographic primitives built on [risc0-bigint2](https://crates.io/crates/risc0-bigint2).
Uses fewer cycles than the patched upstream crates provided by RISC Zero.

## Features

- R0VM accelerated, `no_std`, zero heap allocation
- [Short Weierstrass][sw] curve arithmetic
- Prime field arithmetic (`Fp256`, `Fp384`) with checked and unchecked operations
- ECDSA signing and verification (any compatible curve)
- Modular exponentiation for 256, 384, and 4096-bit integers

## Usage

Target-gate the dependency so the rest of your workspace still builds on the host
(for `cargo check`, IDE tooling, etc.):

```toml
[target.'cfg(all(target_os = "zkvm", target_vendor = "risc0"))'.dependencies]
risc0-crypto = "0.1"
```

Code that uses the crate must sit under the same cfg gate.

## Supported Curves

- [secp256k1](src/curves/secp256k1.rs)
- [secp256r1](src/curves/secp256r1.rs)
- [secp384r1](src/curves/secp384r1.rs)
- [BN254](src/curves/bn254.rs)
- [Grumpkin](src/curves/grumpkin.rs)
- [BLS12-381](src/curves/bls12_381.rs)

## Example

```rust,ignore
use risc0_crypto::{fp, ecdsa::Signature, curves::secp256k1::{self, Affine, Fr}};

// scalar multiplication
let scalar: Fr = fp!("0xdeadbeef");
let point = &Affine::GENERATOR * &scalar;

// ECDSA sign and verify
let sig = Signature::<secp256k1::Config, 8>::sign(&d, &k, hash).unwrap();
assert!(sig.verify(&pubkey, hash));
```

## EVM Precompile Performance

Cycle counts measured on R0VM against the risc0-patched zkVM builds of each upstream library.
`modexp` compares against unpatched
[`aurora-engine-modexp`](https://crates.io/crates/aurora-engine-modexp) - no risc0 fork exists
and revm's default crypto delegates to it.

| Precompile                  | risc0-crypto | upstream   | library          | speedup |
|-----------------------------|-------------:|-----------:|------------------|--------:|
| ecrecover (secp256k1)       |      120,300 |    569,207 | `k256`           |   4.73x |
| p256verify (secp256r1)      |       82,667 |    192,713 | `p256`           |   2.33x |
| EIP-196 G1 add (BN254)      |        2,282 |      9,552 | `substrate-bn`   |   4.19x |
| EIP-196 G1 mul (BN254)      |       68,496 |  1,302,678 | `substrate-bn`   |  19.02x |
| EIP-2537 G1 add (BLS12-381) |        3,394 |     13,625 | `blst`           |   4.01x |
| EIP-2537 G1 MSM, k=1        |      189,395 |  1,316,125 | `blst`           |   6.95x |
| EIP-2537 G1 MSM, k=128      |   19,412,368 | 69,095,071 | `blst`           |   3.56x |
| modexp 256-bit              |       30,566 |    851,596 | `aurora`         |  27.86x |

## Acknowledgements

- All accelerated arithmetic runs the precompiled circuit programs of
  [risc0-bigint2](https://crates.io/crates/risc0-bigint2) (Apache-2.0, RISC Zero). The elliptic
  curve programs are embedded into this crate at build time.
- The field and curve trait design follows [arkworks](https://github.com/arkworks-rs/algebra).
- The ECDSA signature and recovery ID API follows the RustCrypto
  [`ecdsa`](https://github.com/RustCrypto/signatures) crate.

[sw]: https://en.wikipedia.org/wiki/Elliptic_curve#Short_Weierstrass_form
