# Changelog

All notable changes to AMAZES-JCA (Full-Hardened) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Security status:** AMAZES-JCA is an educational cipher and design study.
> It has no security proof and has not undergone public cryptanalysis. It must
> not be used to protect real data. For real workloads use AES-GCM or
> ChaCha20-Poly1305 from a maintained library.
>
> **Authorship:** v0.1 through v0.3 were developed with ChatGPT-4o assistance;
> the v0.4 and v0.5 rework was assisted by a newer AI assistant. Planning,
> ideas, and design decisions were the author's throughout.

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
* **Expanded benchmark suite** comparing against AES-256-GCM/CBC/CTR and
  ChaCha20-Poly1305 in both hardware-accelerated and pure-Python
  (non-accelerated) forms, with AES-ECB as a deliberate failing control.
  Every pure-Python baseline was verified byte-identical (ciphertexts and
  tags) against its library reference before benchmarking. Reported
  variables, all in table format: design overview with ciphertext
  expansion, encryption/decryption latency and throughput, throughput
  scaling across payload sizes (1/10/100 KiB), session/key setup cost,
  per-position diffusion (first/middle/last character), tamper rejection
  across four maul vectors, wrong-key rejection, output
  randomization/determinism checks, entropy against the alphabet ceiling,
  chi-squared/df uniformity with a byte-offset correction for the
  printable-ASCII range (32-126), bias-corrected plaintext-ciphertext
  mutual information, and an IND-CPA left-or-right game (100 trials) with
  the ECB control failing at chance as expected.
* **Deterministic testing hook:** optional `salt` parameter on encryption,
  replacing test-time monkeypatching of the global CSPRNG.

### Changed

* **JCA reworked into a transcript MAC:** the per-event chained hash was
  replaced by a single SHA-256 digest over salt ‖ ordered transcript ‖
  bipolar accumulators ‖ event count. The v0.3 bipolar accumulators
  (`pos_sum`/`neg_sum`, dead code since the chained-hash upgrade) are
  restored into the tag. Equivalent security (SHA-256 is itself a
  Merkle–Damgård chain) and ~17% higher throughput.
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
  the accelerated AEAD fixed-IV path now prepends its nonce so ciphertext
  body extraction is aligned; no-op adjacent-swap artifacts and ECB padding
  errors eliminated.

### Security

* Measured on the new suite: 100% tamper rejection across all four maul
  vectors and 100% wrong-key rejection; entropy 6.50 bits against a
  6.57-bit ceiling (98.9% normalized); chi²/df 0.90; bias-corrected mutual
  information 0.000 bits (ECB control: 2.84). Still an educational design
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

* **Integrity tag (JCA) introduced:** the first tag tracked bipolar jump
  sums (sum of positive jumps, sum of negative jump magnitudes) plus an
  event count, initialized with and bound to the unique 8-character
  session salt to prevent cross-session tag collisions.
* **High-entropy input mixing:** the JCA `record()` function integrates the
  salt, current jump, character value, and rotor shift.
* **Non-linear bit whitening (Hardened versions):** a masking layer in
  `transform()` derived from the session salt, cumulative shift, and
  pointer position, applied as modular addition/subtraction, intended to
  erase the bit bias inherent to printable-only ASCII. The mask adds no
  secrecy beyond the session key: the salt is public and the shift and
  pointer are key-derived, so anyone who can reconstruct the engine state
  can compute it. Reconstructing the state requires the seed and key,
  which a zero-trust deployment exchanges under asymmetric encryption
  anyway. Within that trust boundary the mask obscures the alphabet bias.
* **Decoupled state logic:** the whitening layer operates independently of
  the S-Box mapping, so partial S-Box leakage does not directly reveal
  character substitutions.
* **Deterministic mask seeding:** the whitening mask is regenerated per
  character from a SHA-256 derivation, preventing linear pattern analysis
  across long messages.

### Changed

* **Chained-hash tag:** testing exposed that the bipolar sums are
  commutative, so the tag was blind to transposition (verified
  empirically: 100% collision on 2,000 random event permutations). The tag
  was upgraded to a rolling SHA-256 chain in which every update depends on
  the previous state; a re-check found 0 collisions on genuinely different
  transcripts across 2,000 permutations.
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

Increments to the base engine, each building on the last. No integrity tag
yet.

* **Cumulative geared shifts:** every jump value encountered adds to a
  cumulative shift that offsets the rotor mapping for the current
  character.
* **The reflector (two-pass mirror):** a forward pass followed by a
  reflection pass over the reversed intermediate text from the engine's
  hot state, so a change in one part of the stream is reflected into the
  earlier part.
* **Scheduled state mutation:** the rotor is re-shuffled on an interval
  derived from the jump values.
* **Co-evolutionary mutation:** both the rotor and the key array are
  re-shuffled from a seed derived from the current jump and character
  count.

## [v0.1] - 2026-Q1 (approximate)

### Added

* **Initial text cipher:** a keyed substitution rotor (deterministic
  Fisher-Yates shuffle from the master seed) traversed by a signed
  jump-pointer key array over the 95 printable ASCII characters. No
  integrity mechanism; superseded by the engine increments of v0.2.
