"""Corrected cryptanalytic benchmark: AMAZES-JCA vs. real AEAD/block-cipher modes.

Fixes relative to the original 2025 benchmark script:
  * Comparison targets are REAL implementations from the `cryptography`
    library (AES-256-GCM, ChaCha20-Poly1305, AES-256-CBC/CTR), not
    SHA-256-based simulations. AES-256-ECB is included as a control that
    must FAIL the CPA game, proving the game has teeth. The `cryptography`
    package is OPTIONAL: without it the hardware-accelerated targets are
    skipped and the pure-Python targets still run.
  * Runs standalone: `python benchmark.py` (only the standard library plus
    the local modules amazes_jca, pure_aes, pure_chacha are required).
  * The CPA test is a proper left-or-right indistinguishability game with an
    encryption oracle, not a "c1 != c2" determinism check.
  * The CCA test is a multi-vector tamper matrix (bit-flip, adjacent swap,
    truncation, splicing) over many trials, measuring rejection rates.
  * The diffusion test fixes the salt/nonce/IV so it measures the cipher,
    not per-message randomization.
  * Entropy is reported against each output format's theoretical ceiling
    (log2(95) = 6.57 for AMAZES' 95-symbol alphabet, 8.0 for byte ciphers),
    and a chi-square uniformity test is added.
  * Extended variables, all reported as tables: design overview with
    ciphertext expansion, session/key setup cost, throughput scaling across
    payload sizes, per-position diffusion, plaintext-ciphertext mutual
    information (bias-corrected), wrong-key rejection, and output
    randomization/determinism checks.
"""

import math
import secrets
import time
import collections

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives import padding
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False

import AMAZES_JCA as aj
import pure_chacha
import pure_aes

class PureAesGcmTarget:
    """Pure-Python (non-accelerated) AES-256-GCM."""

    alphabet_ceiling = 8.0
    nonce_size = 12

    def __init__(self, name):
        self.name = name
        self._aes = pure_aes.PureAES(secrets.token_bytes(32))

    def setup(self) -> None:
        self._aes = pure_aes.PureAES(secrets.token_bytes(32))

    def encrypt(self, pt: bytes) -> bytes:
        nonce = secrets.token_bytes(self.nonce_size)
        ct, tag = self._aes.encrypt_gcm(pt, nonce)
        return nonce + ct + tag

    def decrypt(self, pkg: bytes) -> tuple[bytes, bool]:
        n = self.nonce_size
        pt = self._aes.decrypt_gcm(pkg[n:-16], pkg[:n], pkg[-16:])
        return (pt or b""), pt is not None

    def encrypt_fixed_iv(self, pt: bytes) -> bytes:
        ct, tag = self._aes.encrypt_gcm(pt, bytes(self.nonce_size))
        return bytes(self.nonce_size) + ct + tag

    def ciphertext_body(self, pkg: bytes) -> bytes:
        return pkg[self.nonce_size:-16]


class PureAesCtrTarget:
    """Pure-Python AES-256-CTR, NO authentication (non-accelerated)."""

    alphabet_ceiling = 8.0
    nonce_size = 16

    def __init__(self, name):
        self.name = name
        self._aes = pure_aes.PureAES(secrets.token_bytes(32))

    def setup(self) -> None:
        self._aes = pure_aes.PureAES(secrets.token_bytes(32))

    def encrypt(self, pt: bytes) -> bytes:
        nonce = secrets.token_bytes(self.nonce_size)
        return nonce + self._aes.encrypt_ctr(pt, nonce)

    def decrypt(self, pkg: bytes) -> tuple[bytes, bool]:
        n = self.nonce_size
        return self._aes.decrypt_ctr(pkg[n:], pkg[:n]), True

    def encrypt_fixed_iv(self, pt: bytes) -> bytes:
        return bytes(self.nonce_size) + self._aes.encrypt_ctr(pt, bytes(self.nonce_size))

    def ciphertext_body(self, pkg: bytes) -> bytes:
        return pkg[self.nonce_size:]


class PureAesCbcTarget:
    """Pure-Python AES-256-CBC with PKCS7, NO authentication (non-accelerated)."""

    alphabet_ceiling = 8.0
    nonce_size = 16

    def __init__(self, name):
        self.name = name
        self._aes = pure_aes.PureAES(secrets.token_bytes(32))

    def setup(self) -> None:
        self._aes = pure_aes.PureAES(secrets.token_bytes(32))

    def _pad(self, pt: bytes) -> bytes:
        n = 16 - (len(pt) % 16)
        return pt + bytes([n]) * n

    def _unpad(self, pt: bytes) -> bytes:
        n = pt[-1]
        if not 1 <= n <= 16 or pt[-n:] != bytes([n]) * n:
            raise ValueError("bad PKCS7 padding")
        return pt[:-n]

    def encrypt(self, pt: bytes) -> bytes:
        iv = secrets.token_bytes(self.nonce_size)
        return iv + self._aes.encrypt_cbc(self._pad(pt), iv)

    def decrypt(self, pkg: bytes) -> tuple[bytes, bool]:
        n = self.nonce_size
        try:
            return self._unpad(self._aes.decrypt_cbc(pkg[n:], pkg[:n])), True
        except Exception:
            return b"", False

    def encrypt_fixed_iv(self, pt: bytes) -> bytes:
        return bytes(self.nonce_size) + self._aes.encrypt_cbc(self._pad(pt), bytes(self.nonce_size))

    def ciphertext_body(self, pkg: bytes) -> bytes:
        return pkg[self.nonce_size:]

class PureAeadTarget:
    """Pure-Python (non-accelerated) ChaCha20-Poly1305, RFC 8439."""

    alphabet_ceiling = 8.0
    nonce_size = 12

    def __init__(self, name):
        self.name = name
        self._key = secrets.token_bytes(32)

    def setup(self) -> None:
        self._key = secrets.token_bytes(32)

    def encrypt(self, pt: bytes) -> bytes:
        nonce = secrets.token_bytes(self.nonce_size)
        ct, tag = pure_chacha.aead_chacha20_poly1305(self._key, nonce, pt)
        return nonce + ct + tag

    def decrypt(self, ct_pkg: bytes) -> tuple[bytes, bool]:
        n = self.nonce_size
        pt = pure_chacha.aead_decrypt(self._key, ct_pkg[:n], ct_pkg[n:-16], ct_pkg[-16:])
        return (pt or b""), pt is not None

    def encrypt_fixed_iv(self, pt: bytes) -> bytes:
        ct, tag = pure_chacha.aead_chacha20_poly1305(self._key, bytes(self.nonce_size), pt)
        return bytes(self.nonce_size) + ct + tag

    def ciphertext_body(self, ct_pkg: bytes) -> bytes:
        return ct_pkg[self.nonce_size:-16]


class PureStreamTarget:
    """Pure-Python ChaCha20 in CTR-style mode, NO authentication (non-accelerated)."""

    alphabet_ceiling = 8.0
    nonce_size = 12

    def __init__(self, name):
        self.name = name
        self._key = secrets.token_bytes(32)

    def setup(self) -> None:
        self._key = secrets.token_bytes(32)

    def encrypt(self, pt: bytes) -> bytes:
        nonce = secrets.token_bytes(self.nonce_size)
        ks = pure_chacha.chacha20_keystream(self._key, nonce, len(pt))
        return nonce + bytes(a ^ b for a, b in zip(pt, ks))

    def decrypt(self, ct_pkg: bytes) -> tuple[bytes, bool]:
        n = self.nonce_size
        ks = pure_chacha.chacha20_keystream(self._key, ct_pkg[:n], len(ct_pkg) - n)
        return bytes(a ^ b for a, b in zip(ct_pkg[n:], ks)), True

    def encrypt_fixed_iv(self, pt: bytes) -> bytes:
        ks = pure_chacha.chacha20_keystream(self._key, bytes(self.nonce_size), len(pt))
        return bytes(self.nonce_size) + bytes(a ^ b for a, b in zip(pt, ks))

    def ciphertext_body(self, ct_pkg: bytes) -> bytes:
        return ct_pkg[self.nonce_size:]


PAYLOAD = "Standardized Quantum-Resistant Cryptanalysis Payload 2026"


class AmazesTarget:
    name = "AMAZES-JCA"
    alphabet_ceiling = math.log2(95)
    byte_offset = 32
    prefix = aj.SALT_SIZE
    tag = aj.TAG_SIZE

    def __init__(self):
        self.seed, key_str = aj.generate_session_credentials()
        self.key = aj.parse_key_string(key_str)

    def encrypt(self, pt: bytes) -> bytes:
        package, _ = aj.run_amazes(pt.decode(), self.seed, self.key, encrypt=True)
        return package.encode()

    def decrypt(self, ct: bytes) -> tuple[bytes, bool]:
        pt, valid = aj.run_amazes(ct.decode(), self.seed, self.key, encrypt=False)
        return (pt or "").encode(), valid

    def setup(self) -> None:
        self.seed, key_str = aj.generate_session_credentials()
        self.key = aj.parse_key_string(key_str)
        aj.AmazesEngine(list(range(aj.ROTOR_SIZE)), self.key, "ZZ9Qx7#K", self.seed)

    def encrypt_fixed_iv(self, pt: bytes) -> bytes:
        package, _ = aj.run_amazes(pt.decode(), self.seed, self.key, encrypt=True, salt="ZZ9Qx7#K")
        return package.encode()

    def ciphertext_body(self, ct: bytes) -> bytes:
        return ct[self.prefix:-self.tag]


class AeadPackTarget:
    """AEAD (GCM / ChaCha20-Poly1305) with the nonce prepended; decrypt verifies the tag."""

    alphabet_ceiling = 8.0
    nonce_size = 12

    def __init__(self, name, aead):
        self.name = name
        self._aead = aead

    def setup(self) -> None:
        self._aead = type(self._aead)(secrets.token_bytes(32))

    def encrypt(self, pt: bytes) -> bytes:
        nonce = secrets.token_bytes(self.nonce_size)
        return nonce + self._aead.encrypt(nonce, pt, None)

    def decrypt(self, ct: bytes) -> tuple[bytes, bool]:
        try:
            return self._aead.decrypt(ct[:self.nonce_size], ct[self.nonce_size:], None), True
        except Exception:
            return b"", False

    def encrypt_fixed_iv(self, pt: bytes) -> bytes:
        nonce = bytes(self.nonce_size)
        return nonce + self._aead.encrypt(nonce, pt, None)

    def ciphertext_body(self, ct: bytes) -> bytes:
        return ct[self.nonce_size:-16]


class AesKwTarget:
    """AES-CBC / AES-CTR / AES-ECB with random IV prepended (no authentication)."""

    alphabet_ceiling = 8.0

    def __init__(self, name, mode, iv_size):
        self.name = name
        self._mode = mode
        self._iv_size = iv_size
        self._is_ecb = mode is modes.ECB or mode == "ECB"
        self._is_block = self._is_ecb or mode is modes.CBC or mode == "CBC"
        self._key = secrets.token_bytes(32)

    def setup(self) -> None:
        self._key = secrets.token_bytes(32)

    def _cipher(self, iv):
        if self._is_ecb:
            return Cipher(algorithms.AES(self._key), modes.ECB())
        return Cipher(algorithms.AES(self._key), self._mode(iv))

    def _pkcs7_pad(self, pt: bytes) -> bytes:
        p = padding.PKCS7(128).padder()
        return p.update(pt) + p.finalize()

    def _pkcs7_unpad(self, pt: bytes) -> bytes:
        u = padding.PKCS7(128).unpadder()
        return u.update(pt) + u.finalize()

    def encrypt(self, pt: bytes) -> bytes:
        iv = b"" if self._is_ecb else secrets.token_bytes(self._iv_size)
        data = self._pkcs7_pad(pt) if self._is_block else pt
        e = self._cipher(iv).encryptor()
        return iv + e.update(data) + e.finalize()

    def decrypt(self, ct: bytes) -> tuple[bytes, bool]:
        iv_off = 0 if self._is_ecb else self._iv_size
        try:
            d = self._cipher(ct[:iv_off]).decryptor()
            pt = d.update(ct[iv_off:]) + d.finalize()
            if self._is_block:
                pt = self._pkcs7_unpad(pt)
            return pt, True
        except Exception:
            return b"", False

    def encrypt_fixed_iv(self, pt: bytes) -> bytes:
        iv = b"" if self._is_ecb else bytes(self._iv_size)
        data = self._pkcs7_pad(pt) if self._is_block else pt
        e = self._cipher(iv).encryptor()
        return iv + e.update(data) + e.finalize()

    def ciphertext_body(self, ct: bytes) -> bytes:
        return ct[self._iv_size:]


def shannon(b: bytes) -> float:
    if not b:
        return 0.0
    counts = collections.Counter(b)
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def chi_square_uniform(b: bytes, categories: int, byte_offset: int = 0) -> float:
    counts = collections.Counter(b)
    expected = len(b) / categories
    observed = [counts.get(i + byte_offset, 0) for i in range(categories)]
    return sum((o - expected) ** 2 / expected for o in observed) / categories


OVERVIEW_INFO = {
    "AMAZES-JCA": ("stateful mutating polyalphabetic (95-symbol)", 384, "8-char salt", "64-hex"),
    "AES-256-GCM (AES-NI)": ("AEAD (CTR + GHASH)", 256, "12-byte nonce", "16-byte"),
    "ChaCha20-P1305 (accel)": ("AEAD (stream + Poly1305)", 256, "12-byte nonce", "16-byte"),
    "ChaCha20-P1305 (pure Py)": ("AEAD (stream + Poly1305, no accel)", 256, "12-byte nonce", "16-byte"),
    "AES-256-GCM (pure Py)": ("AEAD (CTR + GHASH, no accel)", 256, "12-byte nonce", "16-byte"),
    "AES-256-CTR (pure Py)": ("stream (CTR, no auth, no accel)", 256, "16-byte nonce", "none"),
    "AES-256-CBC (pure Py)": ("block (CBC + PKCS7, no auth, no accel)", 256, "16-byte IV", "none"),
    "AES-256-CBC (AES-NI)": ("block (CBC + PKCS7, no auth)", 256, "16-byte IV", "none"),
    "AES-256-CTR (AES-NI)": ("stream (CTR, no auth)", 256, "16-byte nonce", "none"),
    "ChaCha20-CTR (pure Py)": ("stream (ChaCha20, no auth, no accel)", 256, "12-byte nonce", "none"),
    "AES-256-ECB (control)": ("block (ECB, no auth, deterministic)", 256, "none", "none"),
}


def bench_overview(targets, payload_bytes):
    print("\n--- Overview ---")
    print(f"{'Cipher':<26}{'type':<42}{'key bits':>9}{'randomizer':>14}{'tag':>9}{'expansion %':>13}")
    for t in targets:
        kind, key_bits, rand, tag = OVERVIEW_INFO[t.name]
        ct = t.encrypt(payload_bytes)
        expansion = (len(ct) - len(payload_bytes)) / len(payload_bytes) * 100
        print(f"{t.name:<26}{kind:<42}{key_bits:>9}{rand:>14}{tag:>9}{expansion:>12.1f}%")


def bench_timing(targets, payload_bytes, repeats=20):
    print(f"\n--- Timing ({len(payload_bytes)}-byte payload, avg of {repeats}) ---")
    print(f"{'Cipher':<26}{'enc ms':>10}{'dec ms':>10}{'enc KiB/s':>12}{'dec KiB/s':>12}")
    for t in targets:
        pt = payload_bytes if isinstance(payload_bytes, bytes) else payload_bytes.encode()
        t.encrypt(pt)
        te = time.perf_counter()
        for _ in range(repeats):
            ct = t.encrypt(pt)
        enc_ms = (time.perf_counter() - te) / repeats * 1000
        td = time.perf_counter()
        for _ in range(repeats):
            t.decrypt(ct)
        dec_ms = (time.perf_counter() - td) / repeats * 1000
        enc_kibs = len(pt) / 1024 / (enc_ms / 1000)
        dec_kibs = len(pt) / 1024 / (dec_ms / 1000)
        print(f"{t.name:<26}{enc_ms:>10.3f}{dec_ms:>10.3f}{enc_kibs:>12.1f}{dec_kibs:>12.1f}")


def bench_scaling(targets, sizes=(1024, 10240, 102400), repeats=3):
    print(f"\n--- Throughput scaling (enc KiB/s, best of {repeats}) ---")
    print(f"{'Cipher':<26}" + "".join(f"{s // 1024:>10} KiB" for s in sizes))
    for t in targets:
        row = []
        for size in sizes:
            pt = bytes((i * 7 + 13) % 95 + 32 for i in range(size))
            best = float("inf")
            for _ in range(repeats):
                s = time.perf_counter()
                t.encrypt(pt)
                best = min(best, time.perf_counter() - s)
            row.append(size / 1024 / best)
        print(f"{t.name:<26}" + "".join(f"{v:>10.1f}" for v in row))


def bench_setup(targets, repeats=20):
    print(f"\n--- Session/key setup (avg of {repeats}) ---")
    print(f"{'Cipher':<26}{'setup ms':>10}")
    for t in targets:
        t.setup()
        s = time.perf_counter()
        for _ in range(repeats):
            t.setup()
        ms = (time.perf_counter() - s) / repeats * 1000
        print(f"{t.name:<26}{ms:>10.3f}")
    print("  note: for AMAZES-JCA this is credential generation plus one engine")
    print("  initialization (the per-message analog of a key schedule). Pure-Python")
    print("  baselines have no key schedule; their setup is key generation only.")


def mutual_information(p: bytes, c: bytes) -> float:
    n = min(len(p), len(c))
    p, c = p[:n], c[:n]
    if n == 0:
        return 0.0
    pc = collections.Counter(zip(p, c))
    cp = collections.Counter(p)
    cc = collections.Counter(c)
    mi = 0.0
    for (a, b), joint in pc.items():
        mi += (joint / n) * math.log2((joint / n) / ((cp[a] / n) * (cc[b] / n)))
    bias = ((len(cp) - 1) * (len(cc) - 1)) / (2 * n * math.log(2))
    return max(0.0, mi - bias)


def bench_mutual_info(targets, sample_size=200_000):
    label = sample_size // 1000
    print(f"\n--- Plaintext-ciphertext mutual information ({label}k-char English sample, bias-corrected) ---")
    print(f"{'Cipher':<26}{'MI (bits)':>12}")
    pt = ("the quick brown fox jumps over the lazy dog. " * 5000)[:sample_size].encode()
    for t in targets:
        ct = t.ciphertext_body(t.encrypt(pt))
        print(f"{t.name:<26}{mutual_information(pt, ct):>12.3f}")
    print("  note: MI is biased upward on finite samples; a Miller correction is")
    print("  applied. MI measures first-order statistical leakage only, not key")
    print("  recovery; values are dominated by the sample's own entropy.")


def bench_tamper(targets, trials=30):
    print(f"\n--- Tamper rejection ({trials} trials per vector; rejection %) ---")
    vectors = ["bit-flip", "adjacent-swap", "truncate", "splice"]
    print(f"{'Cipher':<26}" + "".join(f"{v:>15}" for v in vectors))
    for t in targets:
        row = [t.name]
        for vec in vectors:
            rejected = 0
            done = 0
            while done < trials:
                pt = b"the allied forces attack at dawn near the river bridge"
                ct = t.encrypt(pt)
                mid = len(ct) // 2
                if vec == "bit-flip":
                    mauled = ct[:mid] + bytes([ct[mid] ^ 0x01]) + ct[mid + 1:]
                elif vec == "adjacent-swap":
                    mauled = ct[:mid] + bytes([ct[mid + 1], ct[mid]]) + ct[mid + 2:]
                    if mauled == ct:
                        continue
                elif vec == "truncate":
                    mauled = ct[:-1]
                else:
                    other = t.encrypt(b"different message body for splicing test")
                    mauled = ct[:mid] + other[mid:]
                _, valid = t.decrypt(mauled)
                if not valid:
                    rejected += 1
                done += 1
            row.append(f"{rejected / trials * 100:.0f}%")
        print(f"{row[0]:<26}" + "".join(f"{v:>15}" for v in row[1:]))
    print("  note: CBC/CTR have no integrity mechanism; an 'accepted' result means the")
    print("  modification silently decrypted to garbage (or tripped padding by luck).")


def bench_diffusion(targets):
    print("\n--- Diffusion (FIXED salt/nonce/IV; 1 plaintext char changed; ct body only) ---")
    print(f"{'Cipher':<26}{'first char: pos / bits%':>24}{'middle char: pos / bits%':>26}{'last char: pos / bits%':>24}")
    base = b"A" * 40
    variants = [
        ("first", b"B" + b"A" * 39),
        ("middle", b"A" * 20 + b"B" + b"A" * 19),
        ("last", b"A" * 39 + b"B"),
    ]
    for t in targets:
        c0 = t.ciphertext_body(t.encrypt_fixed_iv(base))
        cells = []
        for _, m2 in variants:
            c1 = t.ciphertext_body(t.encrypt_fixed_iv(m2))
            n = min(len(c0), len(c1))
            pos = sum(1 for i in range(n) if c0[i] != c1[i])
            b0 = "".join(f"{x:08b}" for x in c0[:n])
            b1 = "".join(f"{x:08b}" for x in c1[:n])
            bits = sum(a != b for a, b in zip(b0, b1)) / len(b0) * 100
            cells.append(f"{pos} / {bits:.1f}%")
        print(f"{t.name:<26}{cells[0]:>24}{cells[1]:>26}{cells[2]:>24}")


def bench_key_error(targets, trials=20):
    print(f"\n--- Wrong-key rejection & output randomization ({trials} trials) ---")
    print(f"{'Cipher':<26}{'wrong-key rejected':>20}{'fresh-IV differs':>18}{'fixed-IV identical':>20}")
    pt = b"wrong key rejection probe message"
    for t in targets:
        ct = t.encrypt(pt)
        rejected = 0
        for _ in range(trials):
            t.setup()
            _, valid = t.decrypt(ct)
            if not valid:
                rejected += 1
        t.setup()
        fresh_diff = "yes" if t.encrypt(pt) != t.encrypt(pt) else "no"
        fixed_same = "yes" if t.encrypt_fixed_iv(pt) == t.encrypt_fixed_iv(pt) else "no"
        print(f"{t.name:<26}{rejected / trials * 100:>19.0f}%{fresh_diff:>18}{fixed_same:>20}")
    print("  note: unauthenticated modes accept ciphertext under any key; the")
    print("  result decrypts to garbage that only padding luck exposes.")


def bench_entropy(targets):
    print("\n--- Ciphertext entropy & uniformity ---")
    print(f"{'Cipher':<26}{'entropy':>9}{'ceiling':>9}{'norm %':>9}{'chi2/df':>10}")
    for t in targets:
        ct = t.ciphertext_body(t.encrypt(b"The quick brown fox jumps over the lazy dog. " * 20))
        ent = shannon(ct)
        cats = 95 if t.alphabet_ceiling < 8 else 256
        chi = chi_square_uniform(ct, cats, getattr(t, "byte_offset", 0))
        norm = ent / t.alphabet_ceiling * 100
        print(f"{t.name:<26}{ent:>9.3f}{t.alphabet_ceiling:>9.2f}{norm:>8.1f}%{chi:>10.2f}")
    print("  norm % = measured entropy as a fraction of the output format's theoretical")
    print("  maximum (log2(95) = 6.57 for AMAZES' 95-symbol ASCII alphabet, 8.0 for bytes).")


def bench_cpa_game(targets, trials=100):
    """Left-or-right IND-CPA game. Adversary: query enc(m0), enc(m1) once each,
    then must decide which was encrypted in the challenge. Deterministic
    schemes lose instantly; randomized schemes resist this adversary."""
    print(f"\n--- IND-CPA game (left-or-right, {trials} trials, deterministic-match adversary) ---")
    print(f"{'Cipher':<26}{'adversary advantage':>22}")
    m0 = b"attack at dawn   "
    m1 = b"retreat at dusk!!"
    for t in targets:
        wins = 0
        ref0 = t.encrypt(m0)
        ref1 = t.encrypt(m1)
        for _ in range(trials):
            ct = t.encrypt(m0 if secrets.randbits(1) else m1)
            if ct == ref0:
                wins += 1
            elif ct == ref1:
                wins += 1
            else:
                wins += secrets.randbits(1)
        adv = abs(wins / trials - 0.5)
        print(f"{t.name:<26}{adv:>22.3f}")
    print("  note: this game only exposes DETERMINISTIC encryption. For randomized")
    print("  schemes, IND-CPA can only be argued via reduction, not measured by a game.")


def main():
    amazes = AmazesTarget()
    targets = [
        amazes,
        PureAeadTarget("ChaCha20-P1305 (pure Py)"),
        PureAesGcmTarget("AES-256-GCM (pure Py)"),
        PureAesCtrTarget("AES-256-CTR (pure Py)"),
        PureAesCbcTarget("AES-256-CBC (pure Py)"),
        PureStreamTarget("ChaCha20-CTR (pure Py)"),
    ]
    if HAVE_CRYPTOGRAPHY:
        targets += [
            AeadPackTarget("AES-256-GCM (AES-NI)", AESGCM(secrets.token_bytes(32))),
            AeadPackTarget("ChaCha20-P1305 (accel)", ChaCha20Poly1305(secrets.token_bytes(32))),
            AesKwTarget("AES-256-CBC (AES-NI)", modes.CBC, 16),
            AesKwTarget("AES-256-CTR (AES-NI)", modes.CTR, 16),
            AesKwTarget("AES-256-ECB (control)", "ECB", 0),
        ]
    else:
        print("note: the 'cryptography' package is not installed; hardware-accelerated")
        print("targets are skipped. Install it to include them: pip install cryptography")

    bench_overview(targets, PAYLOAD.encode())
    bench_timing(targets, PAYLOAD.encode())
    bench_scaling(targets)
    bench_setup(targets)
    bench_diffusion(targets)
    bench_tamper(targets)
    bench_key_error(targets)
    bench_entropy(targets)
    bench_mutual_info(targets)
    bench_cpa_game(targets)


if __name__ == "__main__":
    main()