# risc0-crypto

Cryptographic primitives built on
[risc0-bigint2](https://crates.io/crates/risc0-bigint2), designed for
use inside [RISC Zero](https://risczero.com/) guest programs.
Uses fewer cycles than the patched upstream crates provided by RISC Zero.

## Features

- R0VM accelerated, `no_std`, zero heap allocation
- [Short Weierstrass](https://en.wikipedia.org/wiki/Elliptic_curve#Short_Weierstrass_form) curve arithmetic
- Prime field arithmetic (`Fp256`, `Fp384`) with checked and unchecked operations
- ECDSA signing and verification (any compatible curve)
- Modular exponentiation for 256, 384, and 4096-bit integers

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

Cycle counts measured on R0VM against the risc0-patched upstream crates
([k256](https://github.com/risc0/RustCrypto-elliptic-curves),
[substrate-bn](https://github.com/risc0/paritytech-bn)).

| Precompile | risc0-crypto | upstream | speedup |
|------------|-------------|----------|---------|
| ecrecover (secp256k1) | 120,811 | 568,195 | 4.7x |
| EIP-196 G1 add (BN254) | 2,282 | 9,552 | 4.2x |
| EIP-196 G1 mul (BN254) | 68,516 | 1,321,073 | 19.3x |

## Testing

Tests require the RISC-V guest environment since risc0-bigint2 uses RISC-V syscalls:

```bash
cargo risczero guest test
```
