# AMAZES-JCA

**Auto Multi-layer ASCII Zone Encryption Salted - Jump-Consistency Authentication (Full-Hardened)**

A symmetric, stateful, mutating, polyalphabetic software rotor cipher for printable ASCII, built from scratch around SHA-256 and modular arithmetic.

> ## ⚠️ Read this first
>
> This project is **for education, learning, and fun**. It is a design study, a demonstration of logic, engineering, and ideas, **not a production cipher**. It has no security proof, has not undergone public cryptanalysis, and must not be used to protect real data. If you need real encryption, use AES-GCM or ChaCha20-Poly1305 from a maintained library (e.g. Python's `cryptography` package).

---

## What it is

AMAZES-JCA encrypts messages over the 95 printable ASCII characters (decimal 32 to 126). One encryption run combines:

- **A keyed substitution rotor (S-Box)**: a Fisher-Yates shuffle driven by a SHA-256 digest chain.
- **A 64-entry signed jump-pointer key array** that steers the engine's traversal.
- **Modular-exponentiation gearing**: the per-character rotor shift step is `pow(3, |jump|, 95)`.
- **Per-character whitening masks** derived from the salt, shift, and pointer.
- **Co-evolutionary mutation**: on a schedule, both the rotor and the key array are re-shuffled from a salt-locked seed that recursively hashes the current rotor state.
- **Subset-sum (target energy) initialization**: the starting pointer is found by walking the key array until the accumulated absolute values reach a salt-derived energy target.
- **The two-pass mirror (reflector)**: a forward pass, then a reflection pass over the reversed intermediate text from the engine's "hot state"; decryption replays the state schedule to reconstruct that hot state.
- **Bipolar JCA**: a homegrown integrity tag computed from the cipher's traversal path: a single SHA-256 digest over the salt, the ordered transcript of per-character events (jump, substituted value, rotor shift), and two bipolar accumulators (sum of positive jumps, sum of negative jump magnitudes).

Output package format: `salt (8 chars) || ciphertext (n chars) || tag (64 hex chars)`.

Everything is homegrown. The only external cryptographic primitive used anywhere is SHA-256 (and `hmac.compare_digest` for timing-safe tag comparison; the MAC itself is not HMAC).

---

## The design timeline: reaching familiar conclusions the hard way

This cipher was built by the author, who started with only a general idea of Enigma-style rotor mechanics and a vague sense of how strong modern ciphers are, with no knowledge of specific standards, modes, or constructions. Every mechanism below was invented to fix a concrete problem encountered along the way, and each fix later turned out to converge on something real cryptography does deliberately. That convergence, not any security claim, is the point of this project.

**v0.1 - The initial text cipher.** A keyed substitution rotor (Fisher-Yates shuffle from a master seed) traversed by a signed jump-pointer key array. A working text cipher with no integrity mechanism.

**v0.2 - Increments to the base engine.** The engine grew in steps: more shifts (a cumulative geared shift offsetting the rotor mapping per character), then the reflector (the two-pass mirror, so a change in one part of the stream is reflected into the earlier part), then scheduled mutations, then mutations of more stuff (co-evolutionary re-shuffling of both the rotor and the key array from the same salt-locked, state-recursive seed). Still no integrity tag.

**v0.3 - The integrity tag (JCA) arrives.** The first tag tracked bipolar jump sums (positive and negative magnitudes) bound to the session salt. Testing then revealed the transposition problem: sums are commutative, so any reordering of the same events produces the same tag. The fix was to make each integrity update depend on the previous one, swallowing the salt, the jump, the character value, and the rotor shift in a fixed order. Only later did it become clear this is *why* real message-authentication constructions are order-sensitive: a MAC that commutes is a MAC that can be mauled by rearrangement. This version also added the per-character whitening mask and pinned the recording point to post-substitution, pre-whitening so both directions of the mirror record identical events. Getting that recording point wrong breaks decryption symmetry entirely, a lesson about why real schemes specify exactly *where* in the pipeline authenticated values are sampled.

**The hardening pass.** Linear pieces were replaced with small "hard problems": the starting pointer became the result of a subset-sum target-energy search, and the rotor gearing became modular exponentiation. Both are honestly labeled as *mini* hard problems: at rotor size 95 they are far too small to be cryptographically hard (`pow(3, x, 95)` has period 36). They demonstrate the *shape* of the idea, not its strength.

**v0.4 - The transcript MAC.** The per-event hash chain was recognized as redundant: SHA-256 is itself a Merkle-Damgård chain, so one digest over the full ordered transcript is equivalent to chaining, and faster. The original bipolar accumulators were folded back into the tag. The project's very first tag idea and its replacement turned out to be combinable.

**v0.5 - Decomposition.** The seed, the key, and the salt became independently generatable components (so separate devices can each generate one), and every mechanism was refactored into a single-purpose function.

The recurring pattern: encounter a concrete failure, fix it with the simplest idea that works, and later discover real cryptography arrived at the same shape for the same reason. That iterative path, from "sums are commutative, that's a bug" to an order-sensitive, salt-bound, direction-symmetric transcript MAC, is what this project documents.

---

## Usage

```python
from amazes_jca import (
    generate_seed,
    generate_key_string,
    parse_key_string,
    encrypt_message,
    decrypt_message,
)

seed = generate_seed()                         # 128-bit session seed
key = parse_key_string(generate_key_string())  # 256-bit key -> signed jump array

package = encrypt_message("hello, world!", seed, key)
plaintext, valid = decrypt_message(package, seed, key)

assert valid and plaintext == "hello, world!"
```

The seed and key are generated by independent functions by design: in a zero-trust setup, one device can generate only the seed and another only the key. The salt is a third, independently generated per-message component.

Decryption verifies the JCA tag and returns `(None, False)` on any modification. Inputs outside the 95-character alphabet, malformed keys, and truncated packages raise `ValueError` rather than failing silently.

A CLI is included: `python amazes_jca.py`.

### Running the test suite and benchmark

Both scripts run from the repository root with Python 3. Keep these files in the
same directory: `amazes_jca.py`, `benchmark.py`, `test_amazes_jca.py`,
`pure_aes.py`, and `pure_chacha.py`.

```text
python test_amazes_jca.py
python benchmark.py
```

The test suite uses only the Python standard library. It runs all 24 tests and
prints a PASS/FAIL line for each one, followed by a final tally.

The benchmark prints ten comparison tables to the CLI:

1. Overview, including ciphertext expansion
2. Encryption and decryption timing
3. Throughput scaling (1, 10, and 100 KiB payloads)
4. Session and key setup time
5. Diffusion, with the changed plaintext character at the first, middle, and last position
6. Tamper rejection (bit-flip, adjacent swap, truncation, splice)
7. Wrong-key rejection and output randomization
8. Ciphertext entropy and uniformity (chi-squared)
9. Mutual information between plaintext and ciphertext
10. IND-CPA left-or-right game

The benchmark always runs the six pure-Python targets: AMAZES-JCA, pure-Python
ChaCha20-Poly1305, pure-Python AES-256-GCM/CTR/CBC, and a pure-Python stream
cipher control. If the optional `cryptography` package is installed
(`pip install cryptography`), five hardware-accelerated targets are added
(AES-256-GCM, ChaCha20-Poly1305, AES-256-CBC, AES-256-CTR, and an AES-ECB
control), for 11 targets in total. Without it, the benchmark prints a note and
skips the accelerated targets. Because every core target is pure Python, a full
run takes on the order of one to two minutes.

---

## Measured characteristics

All numbers below come from this repository's own benchmark suite (`benchmark.py`) and test suite (`test_amazes_jca.py`, 24 tests). The benchmark compares against AES-256-GCM/CBC/CTR and ChaCha20-Poly1305 in both hardware-accelerated and pure-Python (non-accelerated) forms; every pure-Python baseline was verified byte-identical against its library reference before being used. AES-ECB is included as a deliberate failing control.

| Observation | AMAZES-JCA | Comparison |
| --- | --- | --- |
| Tamper rejection (bit-flip, adjacent swap, truncation, splice; 30 trials each) | 100% | tied with all four AEAD targets; CBC/CTR/ECB: 0% (except truncation vs padding) |
| Wrong-key rejection (20 trials) | 100% | tied with AEADs and CBC; CTR/ChaCha-CTR: 0% |
| Ciphertext entropy (ceiling log₂ 95 ≈ 6.57) | 6.50 bits, 98.9% of ceiling | byte ciphers: 96.8 to 97.8% of their 8.0-bit ceiling |
| Output uniformity (chi²/df, byte-offset corrected) | 0.90 (≈ 1.0 is uniform) | byte ciphers: 0.85 to 1.14; ECB control: 1.27 |
| Mutual information, pt vs ct (200k-char English sample, bias-corrected) | 0.000 bits | tied with all AEAD and stream targets; ECB control: 2.838 bits |
| IND-CPA left-or-right game (100 trials) | adversary advantage 0.04 (noise level) | all randomized targets: 0.00 to 0.14; ECB control: 0.500 |
| Fixed-salt diffusion (1 plaintext char changed, any position) | 1 ciphertext position changes (≈ 1% of bits) | same stream-class behavior as GCM/CTR/ChaCha (1 position); CBC propagates 16 to 48 positions |
| Session/key setup | 0.058 ms (credential generation + engine init) | pure-Python AES key schedules: ≈ 0.02 ms; library ciphers: ≈ 0.001 ms |
| Ciphertext expansion (57-byte payload) | 126.3% (72 chars of salt + tag overhead) | AEADs: 49.1%; CTR: 28.1%; CBC: 40.4% |
| Throughput (pure Python, single-threaded) | ≈ 65 KiB/s at 57 bytes, 64 to 69 KiB/s from 1 to 100 KiB | pure-Python AES-GCM: ≈ 103 KiB/s at 57 bytes, ≈ 168 KiB/s bulk; hardware AES-GCM: millions of KiB/s |

Honest framing of what these measure: the IND-CPA game can only expose deterministic encryption; for randomized schemes it cannot *prove* indistinguishability, only fail to find it. The tamper and wrong-key results show the tag detects the mauls tested; they do not establish a security proof. The entropy, uniformity, and mutual-information numbers describe the output distribution, nothing more.

---

## Known limitations

- **No security proof, no public cryptanalysis.** Educational only.
- **Speed.** Per-character SHA-256 derivations and Fisher-Yates re-shuffles make this roughly 2x slower than pure-Python AES-GCM on bulk data and far slower than any accelerated library cipher.
- **Overhead.** The 8-character salt plus 64-character tag add 72 characters to every message, dominating small payloads (126% expansion at 57 bytes).
- **Small hard problems.** The subset-sum initializer is a linear scan, and the modular gearing base has period 36 over a 95-symbol rotor. Both illustrate ideas; neither provides cryptographic hardness at these sizes.
- **Whitening adds no secrecy beyond the key.** The mask inputs are the salt (public) and the shift and pointer (key-derived), so the mask is computable by anyone who can reconstruct the engine state, and reconstructing the state requires the seed and key. Those credentials are exactly what a zero-trust deployment exchanges under asymmetric encryption anyway, the same role RSA plays when it delivers an AES session key. Within that trust boundary the mask does its actual job: obscuring the printable-ASCII bias of the alphabet.
- **95-symbol alphabet.** Caps maximum ciphertext entropy at log₂(95) ≈ 6.57 bits per character by construction.
- **Plaintext-independent state.** State evolution depends only on the key, salt, and character count. This is what makes deterministic warmup replay possible, and it is a deliberate tradeoff.
- **ASCII only.** This is not a binary cipher; a binary variant is future work.

---

## AI disclosure

This project was made by a human-AI collaboration:

- **Planning, ideas, and design decisions: the human author.** Every mechanism, every vulnerability response, and every design pivot originated from the author's reasoning. The author fed each idea, reached the same conclusions independently when vulnerabilities were pointed out, and directed every iteration.
- **The original implementation (v0.1 through v0.3) was assisted by ChatGPT-4o**, an older model. The author skimmed and directed its output, and later found that several of its claims (including benchmark measurements) did not hold up under re-examination.
- **The v0.4 and v0.5 rework (analysis, bug fixing, refactoring, benchmarking, and documentation) was assisted by a newer AI assistant**, which produced measurably better results: a passing test suite, pure-Python cipher baselines verified byte-identical against library references, and corrected measurement methodology.
- All AI-assisted output was reviewed, corrected, and reworked by the author; where AI-generated analysis was wrong, it was found, re-measured, and fixed rather than kept.

See [CHANGE_LOG.md](CHANGE_LOG.md) for the full version history.
