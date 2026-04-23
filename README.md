# risc0-crypto workspace

R0VM-accelerated cryptography for [RISC Zero](https://risczero.com/) guest
programs.

## Crates

- [**risc0-crypto**](crates/crypto) - primitives library: short Weierstrass
  curves, prime field arithmetic (`Fp256`, `Fp384`), ECDSA, and 256/384/4096-bit
  modular exponentiation. Uses fewer cycles than the risc0-patched upstream crates.
- [**risc0-crypto-evm**](crates/evm) - thin EVM-ABI wrappers over the primitives
  (EIP-196 BN254 add/mul, EIP-198 modexp, EIP-7951 P-256 verify, ecrecover,
  SHA-256). Consumed by zeth and kailua - no revm dependency so it never blocks
  a revm upgrade.

See [`crates/crypto/README.md`](crates/crypto/README.md) for the
library walkthrough, benchmark numbers, and usage examples.

## Benchmarks

`bench/` is its own workspace (pulls in `risc0-zkvm` client + the RISC-V guest
build tooling). Run locally with `rzup r0vm` installed:

```bash
cargo run --release --manifest-path bench/Cargo.toml
```

Live benchmark tracking:
[risc0-crypto benchmarks](https://wollac.github.io/risc0-crypto/dev/bench/).
