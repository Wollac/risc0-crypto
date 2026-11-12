# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `risc0-crypto` (breaking): `UnverifiedFp` no longer has `-` and `-=`, which gave unprovable
  executions when the subtrahend exceeded the minuend by more than `p`. Subtraction is defined
  between `Fp` values only, and `-=` on an `Fp` takes an `&Fp`. `FieldOps::sub` and `sub_assign`
  take the subtrahend as `&Fp`. For an unverified minuend, call `FieldOps::sub` with a checked
  subtrahend, or add the negation.
- `risc0-crypto`: `UnverifiedFp` negation is correct for any value, including one `>= p`. It is
  now a multiplication by `p - 1`.
- `risc0-crypto` (breaking): `AffinePoint * scalar` takes a checked `&Fp` scalar only. An
  `UnverifiedFp` scalar needs a `check_ref()` first.
- `risc0-crypto` (breaking): `UnverifiedFp::sqrt` is removed, as it panicked on a value `>= p`.
  Use `Fp::sqrt`, after a `check_ref()` for an unverified value.
- `risc0-crypto`: the BLS12-381 G1 subgroup check uses the curve endomorphism instead of a
  multiplication by the group order, taking about 2.8x fewer cycles.

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
