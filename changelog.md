# Changelog

All notable changes to AMAZES-JCA (Full-Hardened) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Security status:** AMAZES-JCA is an educational cipher and design study.
> It has no security proof and has not undergone public cryptanalysis. It must
> not be used to protect real data. For real workloads use AES-GCM or
> ChaCha20-Poly1305 from a maintained library.

## [Unreleased]

## [v0.5] - 2026-11-14

### Added

* **Independent credential generators:** `generate_seed()` and
  `generate_key_string()` produce the session seed and key separately, so a
  zero-trust deployment can assign each component to a different device.
  `generate_session_credentials()` is retained as a convenience composition
  of the two.
* **Standalone salt generation:** `generate_salt()` extracted from the
  encryption path; the salt is a third, independently generated component.
* **Package format helpers:** `pack_package()` / `unpack_package()` with the
  minimum-length validation moved out of the message procedures.
* **Primary message API:** `encrypt_message()` and `decrypt_message()` as
  independent single-responsibility procedures; `run_amazes()` retained as a
  thin compatibility dispatcher over them.
* **Extracted engine internals** as named single-purpose functions:
  `_subset_sum_pointer()` (target-energy walk), `_gearing_step()`
  (modular-exponentiation gearing), `_whitening_mask()`, `_mutation_seed()`
  (salt-locked recursive state hash), `_invert_sbox()`, `_validate_salt()`,
  and `_replay_hot_state()` (decryption warmup replay).
* **Named size constants:** `SEED_BYTES` (128-bit seed) and `KEY_BYTES`
  (256-bit key string) replacing magic `token_hex()` arguments.

### Changed

* Module restructured into labeled sections (credential generation, key
  material utilities, authentication, engine internals, package format,
  message operations, CLI). Behavior is identical: the full test suite
  (24/24) passes and benchmark results are unchanged.

## [v0.4] - 2026-11-14

### Added

* **Test suite (24 tests):** roundtrip matrix (empty, large, symbol-heavy,
  boundary messages), fresh-salt randomization, wrong-seed/wrong-key
  rejection, six tamper vectors (bit-flip, adjacent swap, truncation, salt
  flip, tag flip, splice), charset-violation rejection, short-package
  rejection, invalid-key rejection, and fixed-salt diffusion check.
* **Benchmark suite** comparing against AES-256-GCM/CBC/CTR and
  ChaCha20-Poly1305 in both hardware-accelerated and pure-Python
  (non-accelerated) forms, with AES-ECB as a deliberate failing control.
  Every pure-Python baseline was verified byte-identical (ciphertexts and
  tags) against its library reference before benchmarking.
* **IND-CPA left-or-right experiment** (100 trials) with the ECB control
  failing at chance as expected.
* **ASCII-aware randomness metrics:** entropy ceilings computed against the
  95-character alphabet (log2(95) ≈ 6.57), normalized entropy percentages,
  and chi-squared/df uniformity with a byte-offset correction for the
  printable-ASCII range (32–126).
* **Deterministic testing hook:** optional `salt` parameter on encryption,
  replacing test-time monkeypatching of the global CSPRNG.

### Changed

* **JCA reworked into a transcript MAC:** the per-event chained hash was
  replaced by a single SHA-256 digest over salt ‖ ordered transcript ‖
  bipolar accumulators ‖ event count. The v0.1 bipolar accumulators
  (`pos_sum`/`neg_sum`, dead code since v0.2) are restored into the tag.
  Equivalent security (SHA-256 is itself a Merkle–Damgård chain) and ~17%
  higher throughput.
* **`hmac` usage narrowed** to `compare_digest` for timing-safe tag
  comparison only; the MAC construction itself remains fully homegrown.

### Fixed

* **Roundtrip failures (Standard and Semi-Hardened lines):** JCA recording
  made direction-symmetric by recording post-substitution, pre-whitening
  values, and the decryption warmup replay restored, so both mirror passes
  record identical events.
* **Silent charset corruption:** out-of-alphabet characters previously
  mapped to index 0 (`C2I.get(char, 0)`); they now raise `ValueError`.
* **Silent key corruption:** `parse_key_string()` silently skipped invalid
  characters; it now validates strictly and raises on non-hex input.
* **Silent package mis-slicing:** packages shorter than salt + tag were
  mis-sliced; they now raise `ValueError`.
* **Benchmark harness:** chi-squared categories aligned with the
  printable-ASCII byte range via a byte-offset correction; diffusion
  measured against the ciphertext body rather than the authentication tag;
  no-op adjacent-swap artifacts and ECB padding errors eliminated.

### Security

* Measured on the new suite: 100% tamper rejection across all four maul
  vectors; entropy 6.505 bits against a 6.57-bit ceiling (99.0% normalized,
  best of the tested targets); chi²/df 0.85. Still an educational design
  study with no security proof.

## [v0.3b] - 2026-Q1 (approximate)

### Changed

* Project moved to a new repository.
* Full-Hardened is now the standard version of AMAZES-JCA and the only
  maintained line; Standard and Semi-Hardened are deprecated.

## [v0.3a] - 2026-Q1 (approximate)

### Announced

* Starting with v0.4, only the Full-Hardened version receives updates.

## [v0.3] - 2026-Q1 (approximate)

### Added

* **Non-linear bit whitening:** a masking layer in `transform()` derived
  from the session salt, cumulative shift, and pointer position, applied as
  modular addition/subtraction, intended to erase the bit bias inherent to
  printable-only ASCII. Effectiveness is minimal at most: the salt is
  public, so the mask is computable by anyone tracking the state. It is
  retained as obfuscation, not secrecy.
* **Decoupled state logic:** the whitening layer operates independently of
  the S-Box mapping, so partial S-Box leakage does not directly reveal
  character substitutions.
* **Deterministic mask seeding:** the whitening mask is regenerated per
  character from a SHA-256 derivation, preventing linear pattern analysis
  across long messages.

### Changed

* **JCA integration (Hardened versions):** recording occurs
  post-substitution but pre-rotation (pre-whitening), so the tag accounts
  for the engine state at the exact moment of encryption and both mirror
  directions record identical values.

### Fixed

* **Symmetry drift:** mutation-triggered state changes now occur at the
  same intervals during decryption, resolved via the state warmup protocol.
* **Zero-bias mitigation:** modular gearing refined to avoid dead states
  with predictable pointer loops. (Note: `pow(3, x, 95)` has period 36, so
  gearing remains a partial mitigation at rotor size 95.)

## [v0.2] - 2026-Q1 (approximate)

### Added

* **Chained-hash state model:** replaced the legacy bipolar-summation tag
  with a rolling SHA-256 hash state for sequence-dependent integrity.
* **High-entropy input mixing:** the JCA `record()` function integrates the
  salt, current jump, character value, and rotor shift.
* **Deterministic session binding:** the JCA state is initialized with the
  unique 8-character session salt to prevent cross-session tag collisions.

### Changed

* **BipolarJCA logic:** shifted from `pos_sum`/`neg_sum` tracking to a
  cumulative update context capturing the entire execution path. (The
  accumulators remained as dead code until v0.4 restored them into the
  transcript digest.)
* **Tag generation:** the final tag is the terminal result of the hash
  chain, unique to the specific order of characters in the message,
  emitted as a 64-character hex string (256 bits).

### Fixed

* **Transposition collisions:** the bipolar-summation tag collided on every
  reordering of events (the sums are commutative). Order-dependent chaining
  resolves this; verified empirically with 0 collisions on genuinely
  different transcripts across 2,000 random permutations.
* **State de-synchronization sensitivity:** any single-character
  modification to the ciphertext desynchronizes the mutation schedule and
  shift logic, collapsing the authentication chain.

## [v0.1] - 2026-Q1 (approximate, reconstructed)

* Initial Full-Hardened implementation. Authentication used bipolar
  summation only (`pos_sum`/`neg_sum` with an event count), which was
  order-insensitive and blind to transposition; superseded by v0.2.
  Reconstructed from code vestiges and the v0.2 changelog entry — no
  original changelog entry survives.
