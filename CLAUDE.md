# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
cargo check --tests        # Type check (~0.08s)
cargo clippy --tests       # Lint (expect self-convention warnings - intentional for const fn)
cargo +nightly fmt         # Format (requires nightly for rustfmt.toml options)
cargo doc --lib            # Generate docs

# Tests require the RISC-V guest environment (risc0-bigint2 uses RISC-V syscalls)
cargo risczero guest test

# With guest execution metrics (total cycles, bigint2 syscall counts):
RUST_LOG=info RISC0_INFO=true cargo risczero guest test
```

Tests **cannot** run on the host - `risc0-bigint2` field and EC operations are backed by RISC-V syscalls.

## Architecture

This is a `no_std` Rust library providing ergonomic elliptic curve and field arithmetic over `risc0-bigint2`. Edition 2024.

### Core Abstractions (layered bottom-up)

1. **`BigInt<N>`** (`src/bigint.rs`) - Fixed-size integer as `[u32; N]` little-endian limbs. Supports const hex parsing (`bigint!()` macro), big-endian byte conversion, `bit_len()` (const fn, used to auto-derive `MODULUS_BIT_LEN` on `Fp`), and `const_eq()` / `const_lt()` for const-context comparisons. `PartialEq` and `Ord` use limb-by-limb ops rather than derived memcmp - memcmp is expensive on R0VM.

2. **`Fp<P, N>`** (`src/field/`) - Prime field element generic over a config type `P` and limb count `N`. Type aliases: `Fp256<P>` (N=8, 256-bit) and `Fp384<P>` (N=12, 384-bit).
   - `R0FieldConfig<N>` trait: implement to define a new field (just set `MODULUS`)
   - `FpConfig<N>` trait: internal dispatch layer with unsafe `fp_*` pointer-based methods and safe `fp_reduce`; a blanket impl in `ops.rs` derives it from every `R0FieldConfig`
   - Operator overloads (`+`, `-`, `*`, unary `-`) produce canonical results in `[0, p)`
   - For intermediate computations, use `Unreduced<P, N>` (skips canonicality checks), then call `.check()` (assert canonical) or `.reduce()` (force canonical) to convert back to `Fp`
   - `Fp` implements `AsRef<Unreduced<P, N>>`, so `Fp` values can be used directly in `Unreduced` arithmetic and as scalars in `AffinePoint * scalar`

3. **`AffinePoint<C, N>`** (`src/curve/`) - Short Weierstrass curve point in affine coordinates.
   - **On-curve invariant**: every `AffinePoint` satisfies `y² = x³ + ax + b` (or is identity). Subgroup membership is not enforced.
   - Constructors: `new()` (on-curve check), `new_in_subgroup()` (on-curve + subgroup), `unsafe new_unchecked()` (external), `pub(crate) from_xy()` (internal)
   - `CurveConfig<N>` trait: implement to define a new curve (base/scalar field configs, coefficients A/B, generator, `type Ops` for backend)
   - `CurveOps<C, N>` trait: EC arithmetic interface (`add`, `double` + in-place variants). `R0VMCurveOps` is the R0VM backend.
   - Operator overloads: `+`, `-` (binary and unary), `*` (scalar mul)
   - Inherent methods `double()` / `double_assign()` for explicit point doubling
   - Coordinates may not be canonical after arithmetic - access via `xy()` / `xy_ref()` (check) or `xy_unreduced()` (deferred)
   - EC operations in `R0VMCurveOps` call `sys_bigint2_3`/`sys_bigint2_4` directly with pre-compiled circuit blobs (copied from `risc0-bigint2` into `OUT_DIR` by `build.rs` - see that file for rationale)

4. **Backend modules** (`src/field/ops.rs`, `src/curve/ops.rs`) - Each contains the FFI dispatch and blanket impl for its domain. Replacing either module is all that's needed to retarget to a different backend.

### Supported Curves (`src/curves/`)

| Curve | N | A | B | Cofactor |
|-------|---|---|---|----------|
| secp256k1 | 8 | 0 | 7 | 1 |
| secp256r1 | 8 | -3 | ... | 1 |
| BN254 | 8 | 0 | 3 | 1 |
| Grumpkin | 8 | 0 | -17 | 1 |
| secp384r1 | 12 | -3 | ... | 1 |
| BLS12-381 | 12 | 0 | 4 | has cofactor |

Each curve file follows the same pattern: `FqConfig` (base field), `FrConfig` (scalar field), `Config` (curve), and type aliases `Fq`, `Fr`, `Affine`.

Grumpkin reuses BN254's fields (its base field is BN254's scalar field and vice versa).

### Key Design Decisions

- **Const-time construction**: `fp!()` and `bigint!()` macros validate at compile time
- **Zero heap allocation**: all types are stack-allocated, `no_std` compatible
- **Cofactor-1 optimization**: curves with cofactor 1 override `is_in_correct_subgroup()` to return `true`, skipping the expensive `[order]P = O` check
- **`Unreduced` check vs reduce**: `Unreduced` holds possibly non-canonical field values. Arithmetic is always sound inside. When leaving the struct (extracting an `Fp` or producing a field-semantic `bool`), two strategies: `check` asserts the value is already canonical, `reduce` forces it canonical. The same choice applies to comparisons.

## Style

- Max line width is 100 (code and comments). Wrap comments and docs as close to 100 as possible - do not leave short lines when text could fill the line
- Comments: lowercase start unless a full sentence; prefer short bullet-point style over prose
- No blank lines between `use` statements
- See `rustfmt.toml` for formatting config
- Math notation in comments/docs:
  - Unicode superscripts for exponentiation: `y² = x³`, `self⁻¹ mod p`
  - Bracket notation for scalar multiplication, no `*`: `[k]P`, `[order]P == O`
  - ASCII for prose operators: `in`, `->`, `>=` (not `∈`, `→`, `≥`)

## Adding a New Curve

1. Create `src/curves/<name>.rs` with `FqConfig`, `FrConfig`, `Config` (implementing `CurveConfig<N>`), and type aliases
2. Add `pub mod <name>;` to `src/curves/mod.rs`
3. Include standard tests: `discriminant_is_nonzero()`, `generator_is_valid()`, and `mul_group_order_is_identity()`
