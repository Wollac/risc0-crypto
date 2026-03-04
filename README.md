# risc0-crypto

Cryptographic primitives built on
[risc0-bigint2](https://crates.io/crates/risc0-bigint2), designed for
use inside [RISC Zero](https://risczero.com/) guest programs.
Uses fewer cycles than the patched upstream crates provided by RISC Zero.

## Features

- R0VM accelerated, `no_std`, zero heap allocation
- [Short Weierstrass](https://en.wikipedia.org/wiki/Elliptic_curve#Short_Weierstrass_form) curve arithmetic
- Prime field arithmetic (`Fp256`, `Fp384`) with checked and unchecked operations
- Modular exponentiation for 256, 384, and 4096-bit integers

## Supported Curves

- [secp256k1](src/curves/secp256k1.rs)
- [secp256r1](src/curves/secp256r1.rs)
- [BN254](src/curves/bn254.rs)
- [Grumpkin](src/curves/grumpkin.rs)
- [BLS12-381](src/curves/bls12_381.rs)

## Example

```rust,ignore
use risc0_crypto::curves::secp256k1::{Affine, Fr};
use risc0_crypto::fp;

let scalar: Fr = fp!("0xdeadbeef");
let point = Affine::generator() * scalar;
```

## Testing

Tests require the RISC-V guest environment since risc0-bigint2 uses RISC-V syscalls:

```bash
cargo risczero guest test
```
