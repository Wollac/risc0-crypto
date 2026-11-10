# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `risc0-crypto`: zkVM-accelerated cryptographic primitives built on
  [`risc0-bigint2`](https://crates.io/crates/risc0-bigint2).
  - Short Weierstrass curves: secp256k1, secp256r1, secp384r1, BN254, Grumpkin, BLS12-381.
  - Prime field arithmetic (`Fp256`, `Fp384`) with checked (`Fp`) and unchecked (`UnverifiedFp`)
    variants.
  - ECDSA signing, verification, and public-key recovery (`Signature`, `RecoverableSignature`).
  - Modular exponentiation for 256-, 384-, and 4096-bit integers.
- `risc0-crypto-evm`: zkVM-accelerated EVM precompile primitives backed by `risc0-crypto`.
  - `bn254_g1_add`, `bn254_g1_mul` (EIP-196)
  - `modexp` (EIP-198)
  - `secp256k1_ecrecover`
  - `secp256r1_verify` (EIP-7951)
  - `sha256` (via `risc0-zkp`)
