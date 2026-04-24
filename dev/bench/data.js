window.BENCHMARK_DATA = {
  "lastUpdate": 1777047785099,
  "repoUrl": "https://github.com/Wollac/risc0-crypto",
  "entries": {
    "risc0-crypto benchmarks": [
      {
        "commit": {
          "author": {
            "email": "welzwo@gmail.com",
            "name": "Wolfgang Welz",
            "username": "Wollac"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3539b39cfa82fd353f0d4fa84c31a34e3a10723f",
          "message": "Add CI benchmarks for cycle counting (#16)\n\n* Add CI benchmarks for cycle counting (#13)\n\nCheck in the benchmark harness and add a CI job that tracks cycle\ncounts using github-action-benchmark. The host binary now supports\n--json <path> to emit results in customSmallerIsBetter format.\n\n* Install r0vm in bench CI job\n\nThe risc0-zkvm executor needs the r0vm binary at runtime to execute\nthe guest ELF.\n\n* Clean working tree before github-action-benchmark\n\ncargo run modifies bench/Cargo.lock during the build, which prevents\nthe action from switching to the gh-pages branch.\n\n* Update lockfiles and use --locked in CI\n\nRegenerate bench/Cargo.lock and bench/guest/Cargo.lock so they match\ncurrent crates.io state. Use --locked in CI to fail fast if they\ndrift.\n\n* Grant write permissions to bench job for gh-pages push\n\nThe github-action-benchmark action needs contents:write to push\nbenchmark data to the gh-pages branch.\n\n* Consolidate benchmarks by removing redundant entries\n\nRemove 10 benchmarks that duplicate existing ones:\n- field add_assign/mul_assign: same backend as add/mul (just += and *= syntax)\n- ec is_on_curve: cheap validation check, not a hot path\n- ec point_add_assign: same backend as point_add (just += syntax)\n- ecdsa rsign: nearly identical to sign; recovery path already covered by ecrecover\n\nReduces total benchmark count from ~35 to ~25 while keeping all\ndistinct operations: field (add, mul, inverse), EC (double, add,\nscalar_mul), ECDSA (sign, verify, recover), EIP comparisons, and modexp.\n\nhttps://claude.ai/code/session_01P1ZS7kqPxKDmQwAVPtwLVk\n\n* Restore ec/*/is_on_curve benchmark\n\nThis benchmark is sensitive to performance regressions and worth\ntracking as a stability indicator.\n\nhttps://claude.ai/code/session_01P1ZS7kqPxKDmQwAVPtwLVk\n\n* Reduce bench dependencies by disabling unused features\n\nHost:\n- risc0-zkvm: drop `bonsai` feature (remote proving not needed for local\n  benchmarks), removing reqwest and ~100 transitive packages\n- regex: set default-features = false, features = [\"std\", \"perf\"]\n  (bench regex is ASCII-only; unicode features are still unified in by\n  lazy-regex, but explicit is cleaner)\n- tabular: drop unicode-width (bench names are ASCII)\n\nGuest:\n- risc0-zkvm: set default-features = false (host-only features like\n  client/bonsai are already cfg'd out on the zkvm target, but this\n  keeps the lockfile lean)\n\nTotal packages: 370 -> 268 (host), lockfiles shrink by ~3,200 lines.\n\nhttps://claude.ai/code/session_01P1ZS7kqPxKDmQwAVPtwLVk\n\n* Simplify and fix benchmark code after review\n\n- Fix bls12_381_g1_add_risc0 to use new_in_subgroup (EIP-2537 requires\n  subgroup checks; the add benchmark was understating cycle cost)\n- Fix point_add benchmark to use a distinct point (GENERATOR.double())\n  instead of adding G+G which exercises the doubling special case\n- Rename FIELD_ITERS -> BENCH_ITERS (used for both field and EC benchmarks)\n- Remove unnecessary manual padding in read_scalar_risc0\n  (BigInt::from_be_bytes already handles short inputs)\n- Assert ecdsa_verify result to catch silent failures\n\nhttps://claude.ai/code/session_01P1ZS7kqPxKDmQwAVPtwLVk\n\n* Pre-format cycle markers outside timed regions\n\nformat!() allocates on the heap, adding measurement noise when called\ninside the timed span (between cycle-start and cycle-end markers).\nMove all format!() calls before the timed region in bench_field,\nbench_ec, bench_ecdsa macros, and the MSM loop.\n\nhttps://claude.ai/code/session_01P1ZS7kqPxKDmQwAVPtwLVk\n\n* Revert bls12_381_g1_add_risc0 subgroup check back to on-curve only\n\nThe add benchmark measures point addition cost, not input validation.\nThe subgroup check (new_in_subgroup) adds two 255-bit scalar muls to\nthe timed region, dominating the measurement. The MSM benchmark already\nuses new_in_subgroup where EIP-2537 requires it.\n\nhttps://claude.ai/code/session_01P1ZS7kqPxKDmQwAVPtwLVk\n\n* Revert guest risc0-zkvm default-features change\n\nThe default-features = false on the guest's risc0-zkvm was cosmetic\n(host code is cfg-gated out on the zkvm target) but caused a full\nlockfile regeneration that changed dependency versions. Restore the\noriginal guest Cargo.toml and Cargo.lock to match the known-working\nstate.\n\nhttps://claude.ai/code/session_01P1ZS7kqPxKDmQwAVPtwLVk\n\n* Revert \"Pre-format cycle markers outside timed regions\"\n\nThis reverts commit 7e867ded2e16db3e1a6b5df0641e5b5be401bd0a.\n\n* Remove patched-crate comparisons from benchmarks\n\nDrop k256, substrate-bn, and blst comparison benchmarks and their\ndependencies. Precompile comparisons can be added in a follow-up PR.\n\n* Format MSM benchmark topic names\n\nUse underscore separator (msm_1, msm_128) instead of path separator\nto avoid an extra grouping level in the output table.\n\n* Drop point_double and 4096-bit full-exponent benchmarks\n\npoint_double is covered by scalar_mul (~256 doubles per run).\n4096-bit full-width exponents don't occur on-chain - real modexp\ncalls at that size use tiny exponents (e=65537 for RSA verify),\nwhich we already benchmark.\n\n* Only push benchmark data on main, always comment on PRs\n\nauto-push only on main avoids writing intermediate data from PR\nbranches. comment-always on PRs shows the benchmark comparison\neven when there is no regression.\n\n* Move GITHUB_PATH setup into rzup install step\n\nAdd ~/.risc0/bin to GITHUB_PATH right after installing rzup, so\nsubsequent steps can find it without a redundant export.\n\n* Apply same rzup PATH fix to Guest Test job\n\n* Grant pull-requests:write for benchmark PR comments\n\n* Reduce bench timeout to 30 minutes\n\n* Remove explicit bench timeout, use GitHub default\n\n* Refactor bench guest: real mainnet data, bench! macro, cleanup\n\n- Add bench! macro that pre-formats cycle markers before the timed\n  region, avoiding formatting cycles in measurements\n- Replace synthetic test inputs with real Ethereum mainnet precompile\n  call data (ecrecover, EIP-196, EIP-2537, modexp) sourced via Dune\n- Use hex-literal crate for readable inline test vectors\n- Extract shared decode/encode helpers for BN254 and BLS12-381\n- Remove setup functions, asserts, and redundant black_box on inputs\n- Shrink modexp exponent types to minimum required size\n\n* Clean up bench: add timeout, trim comments, scope BLS types\n\n* Restore doc comments on bench helper functions\n\n* Remove redundant ecrecover doc comment and EC curve list\n\n---------\n\nCo-authored-by: Claude <noreply@anthropic.com>",
          "timestamp": "2026-04-14T15:07:09+02:00",
          "tree_id": "6148104ff31ebffa46aa41ec6e817fbe79ce3206",
          "url": "https://github.com/Wollac/risc0-crypto/commit/3539b39cfa82fd353f0d4fa84c31a34e3a10723f"
        },
        "date": 1776172219017,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "ecrecover",
            "value": 119233,
            "unit": "cycles"
          },
          {
            "name": "eip196/add",
            "value": 2357,
            "unit": "cycles"
          },
          {
            "name": "eip196/mul",
            "value": 71200,
            "unit": "cycles"
          },
          {
            "name": "eip2537/add",
            "value": 3207,
            "unit": "cycles"
          },
          {
            "name": "eip2537/msm_1",
            "value": 184186,
            "unit": "cycles"
          },
          {
            "name": "eip2537/msm_128",
            "value": 17981471,
            "unit": "cycles"
          },
          {
            "name": "field/secp256r1/add",
            "value": 85,
            "unit": "cycles"
          },
          {
            "name": "field/secp256r1/mul",
            "value": 93,
            "unit": "cycles"
          },
          {
            "name": "field/secp256r1/inverse",
            "value": 101,
            "unit": "cycles"
          },
          {
            "name": "field/secp384r1/add",
            "value": 152,
            "unit": "cycles"
          },
          {
            "name": "field/secp384r1/mul",
            "value": 170,
            "unit": "cycles"
          },
          {
            "name": "field/secp384r1/inverse",
            "value": 179,
            "unit": "cycles"
          },
          {
            "name": "ec/secp256r1/is_on_curve",
            "value": 355,
            "unit": "cycles"
          },
          {
            "name": "ec/secp256r1/point_add",
            "value": 350,
            "unit": "cycles"
          },
          {
            "name": "ec/secp256r1/scalar_mul",
            "value": 68230,
            "unit": "cycles"
          },
          {
            "name": "ec/secp256r1/ecdsa_sign",
            "value": 67421,
            "unit": "cycles"
          },
          {
            "name": "ec/secp256r1/ecdsa_verify",
            "value": 83743,
            "unit": "cycles"
          },
          {
            "name": "ec/secp256r1/ecdsa_recover",
            "value": 103904,
            "unit": "cycles"
          },
          {
            "name": "ec/secp384r1/is_on_curve",
            "value": 445,
            "unit": "cycles"
          },
          {
            "name": "ec/secp384r1/point_add",
            "value": 464,
            "unit": "cycles"
          },
          {
            "name": "ec/secp384r1/scalar_mul",
            "value": 107264,
            "unit": "cycles"
          },
          {
            "name": "ec/secp384r1/ecdsa_sign",
            "value": 105758,
            "unit": "cycles"
          },
          {
            "name": "ec/secp384r1/ecdsa_verify",
            "value": 167583,
            "unit": "cycles"
          },
          {
            "name": "ec/secp384r1/ecdsa_recover",
            "value": 227239,
            "unit": "cycles"
          },
          {
            "name": "modexp/256bit",
            "value": 26891,
            "unit": "cycles"
          },
          {
            "name": "modexp/384bit",
            "value": 49215,
            "unit": "cycles"
          },
          {
            "name": "modexp/4096bit_e65537",
            "value": 10370,
            "unit": "cycles"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "welzwo@gmail.com",
            "name": "Wolfgang Welz",
            "username": "Wollac"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "320a9dfe61fe0ffc1ff2f732d894dfa9647a188c",
          "message": "Link to live benchmark dashboard in README (#17)",
          "timestamp": "2026-04-14T19:23:37+02:00",
          "tree_id": "943fcaeb64d9c43ab5a8df212c932cc06bb4aaa2",
          "url": "https://github.com/Wollac/risc0-crypto/commit/320a9dfe61fe0ffc1ff2f732d894dfa9647a188c"
        },
        "date": 1776187635780,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "ecrecover",
            "value": 119233,
            "unit": "cycles"
          },
          {
            "name": "eip196/add",
            "value": 2357,
            "unit": "cycles"
          },
          {
            "name": "eip196/mul",
            "value": 71200,
            "unit": "cycles"
          },
          {
            "name": "eip2537/add",
            "value": 3207,
            "unit": "cycles"
          },
          {
            "name": "eip2537/msm_1",
            "value": 184186,
            "unit": "cycles"
          },
          {
            "name": "eip2537/msm_128",
            "value": 17981471,
            "unit": "cycles"
          },
          {
            "name": "field/secp256r1/add",
            "value": 85,
            "unit": "cycles"
          },
          {
            "name": "field/secp256r1/mul",
            "value": 93,
            "unit": "cycles"
          },
          {
            "name": "field/secp256r1/inverse",
            "value": 101,
            "unit": "cycles"
          },
          {
            "name": "field/secp384r1/add",
            "value": 152,
            "unit": "cycles"
          },
          {
            "name": "field/secp384r1/mul",
            "value": 170,
            "unit": "cycles"
          },
          {
            "name": "field/secp384r1/inverse",
            "value": 179,
            "unit": "cycles"
          },
          {
            "name": "ec/secp256r1/is_on_curve",
            "value": 355,
            "unit": "cycles"
          },
          {
            "name": "ec/secp256r1/point_add",
            "value": 350,
            "unit": "cycles"
          },
          {
            "name": "ec/secp256r1/scalar_mul",
            "value": 68230,
            "unit": "cycles"
          },
          {
            "name": "ec/secp256r1/ecdsa_sign",
            "value": 67421,
            "unit": "cycles"
          },
          {
            "name": "ec/secp256r1/ecdsa_verify",
            "value": 83743,
            "unit": "cycles"
          },
          {
            "name": "ec/secp256r1/ecdsa_recover",
            "value": 103904,
            "unit": "cycles"
          },
          {
            "name": "ec/secp384r1/is_on_curve",
            "value": 445,
            "unit": "cycles"
          },
          {
            "name": "ec/secp384r1/point_add",
            "value": 464,
            "unit": "cycles"
          },
          {
            "name": "ec/secp384r1/scalar_mul",
            "value": 107264,
            "unit": "cycles"
          },
          {
            "name": "ec/secp384r1/ecdsa_sign",
            "value": 105758,
            "unit": "cycles"
          },
          {
            "name": "ec/secp384r1/ecdsa_verify",
            "value": 167583,
            "unit": "cycles"
          },
          {
            "name": "ec/secp384r1/ecdsa_recover",
            "value": 227239,
            "unit": "cycles"
          },
          {
            "name": "modexp/256bit",
            "value": 26891,
            "unit": "cycles"
          },
          {
            "name": "modexp/384bit",
            "value": 49215,
            "unit": "cycles"
          },
          {
            "name": "modexp/4096bit_e65537",
            "value": 10370,
            "unit": "cycles"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "welzwo@gmail.com",
            "name": "Wolfgang Welz",
            "username": "Wollac"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "4042fe8933cd71b36e0969c6e7d52c994cc43f86",
          "message": "Add risc0-crypto-evm crate and restructure as workspace (#18)\n\n* Add risc0-crypto-evm crate and restructure as workspace\n\n- Introduce `crates/evm/` (`risc0-crypto-evm`): EVM-ABI wrappers over the\n  primitives (BN254 G1 add/mul, modexp, P-256 verify, ecrecover, SHA-256).\n  Ported from boundless-xyz/zeth#232. No revm dependency so zeth and kailua\n  can share precompile primitives across different revm versions.\n- Move the primitives into `crates/crypto/`; root becomes a virtual workspace.\n  `bench/` stays standalone via its own `[workspace]` table.\n- CI flags updated for the workspace layout; README split into a short root\n  index and the existing library walkthrough under the crate.\n\n* Hoist workspace lints, trim comments, shrink modexp allocs\n\n- Move duplicated [lints.*] blocks to root [workspace.lints], use lints.workspace = true in members\n- Drop WHAT comments in secp256k1/secp256r1/modexp that restated the doc comments\n- modexp_n: write the BigInt via a stack scratch so only the modulus.len()-sized\n  output hits the heap (was two heap allocs)",
          "timestamp": "2026-04-24T18:19:50+02:00",
          "tree_id": "bceefac0397ebf2018d27bf665b886f4aa0c1b87",
          "url": "https://github.com/Wollac/risc0-crypto/commit/4042fe8933cd71b36e0969c6e7d52c994cc43f86"
        },
        "date": 1777047784350,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "ecrecover",
            "value": 119233,
            "unit": "cycles"
          },
          {
            "name": "eip196/add",
            "value": 2357,
            "unit": "cycles"
          },
          {
            "name": "eip196/mul",
            "value": 71200,
            "unit": "cycles"
          },
          {
            "name": "eip2537/add",
            "value": 3207,
            "unit": "cycles"
          },
          {
            "name": "eip2537/msm_1",
            "value": 184186,
            "unit": "cycles"
          },
          {
            "name": "eip2537/msm_128",
            "value": 17981471,
            "unit": "cycles"
          },
          {
            "name": "field/secp256r1/add",
            "value": 85,
            "unit": "cycles"
          },
          {
            "name": "field/secp256r1/mul",
            "value": 93,
            "unit": "cycles"
          },
          {
            "name": "field/secp256r1/inverse",
            "value": 101,
            "unit": "cycles"
          },
          {
            "name": "field/secp384r1/add",
            "value": 152,
            "unit": "cycles"
          },
          {
            "name": "field/secp384r1/mul",
            "value": 170,
            "unit": "cycles"
          },
          {
            "name": "field/secp384r1/inverse",
            "value": 179,
            "unit": "cycles"
          },
          {
            "name": "ec/secp256r1/is_on_curve",
            "value": 355,
            "unit": "cycles"
          },
          {
            "name": "ec/secp256r1/point_add",
            "value": 350,
            "unit": "cycles"
          },
          {
            "name": "ec/secp256r1/scalar_mul",
            "value": 68230,
            "unit": "cycles"
          },
          {
            "name": "ec/secp256r1/ecdsa_sign",
            "value": 67421,
            "unit": "cycles"
          },
          {
            "name": "ec/secp256r1/ecdsa_verify",
            "value": 83743,
            "unit": "cycles"
          },
          {
            "name": "ec/secp256r1/ecdsa_recover",
            "value": 103904,
            "unit": "cycles"
          },
          {
            "name": "ec/secp384r1/is_on_curve",
            "value": 445,
            "unit": "cycles"
          },
          {
            "name": "ec/secp384r1/point_add",
            "value": 464,
            "unit": "cycles"
          },
          {
            "name": "ec/secp384r1/scalar_mul",
            "value": 107264,
            "unit": "cycles"
          },
          {
            "name": "ec/secp384r1/ecdsa_sign",
            "value": 105758,
            "unit": "cycles"
          },
          {
            "name": "ec/secp384r1/ecdsa_verify",
            "value": 167583,
            "unit": "cycles"
          },
          {
            "name": "ec/secp384r1/ecdsa_recover",
            "value": 227239,
            "unit": "cycles"
          },
          {
            "name": "modexp/256bit",
            "value": 26891,
            "unit": "cycles"
          },
          {
            "name": "modexp/384bit",
            "value": 49215,
            "unit": "cycles"
          },
          {
            "name": "modexp/4096bit_e65537",
            "value": 10370,
            "unit": "cycles"
          }
        ]
      }
    ]
  }
}