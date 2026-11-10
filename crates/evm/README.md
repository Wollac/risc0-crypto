# risc0-crypto-evm

**This crate only builds and links for `riscv32im-risc0-zkvm-elf`.** Use it from
[RISC Zero](https://risczero.com/) guest code only - linking from a host binary fails by design,
since the primitives call `risc0-bigint2` syscalls that only the R0VM guest runtime defines.

> ⚠️ **This crate has not been independently audited.**

R0VM-accelerated EVM precompile primitives, layered on top of
[risc0-crypto](https://crates.io/crates/risc0-crypto). Plain functions, no revm dependency,
no `Crypto` trait impl - consumers write a ~50-line adapter that implements whichever
`revm_precompile::Crypto` version they are on by delegating to these functions, so this crate
never blocks a revm upgrade.

## Precompiles

- `bn254_g1_add`, `bn254_g1_mul` ([EIP-196][eip196])
- `modexp` ([EIP-198][eip198])
- `secp256k1_ecrecover`
- `secp256r1_verify` ([EIP-7951][eip7951] / [RIP-7212][rip7212])
- `sha256`

## Usage

Target-gate the dependency so the rest of your workspace still builds on the host
(for `cargo check`, IDE tooling, etc.):

```toml
[target.'cfg(all(target_os = "zkvm", target_vendor = "risc0"))'.dependencies]
risc0-crypto-evm = "0.1"
```

The `impl Crypto for R0vmCrypto { ... }` adapter must sit under the same cfg gate.

[eip196]: https://eips.ethereum.org/EIPS/eip-196
[eip198]: https://eips.ethereum.org/EIPS/eip-198
[eip7951]: https://eips.ethereum.org/EIPS/eip-7951
[rip7212]: https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md
