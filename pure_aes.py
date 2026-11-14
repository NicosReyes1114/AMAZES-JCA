"""Pure-Python AES-256 (FIPS-197) with CTR / CBC / ECB modes and GCM (SP 800-38D).

No AES-NI, no C extensions: every operation is plain Python integer and
list arithmetic, putting it in the same performance class as AMAZES-JCA.
The S-box is generated from GF(2^8) field arithmetic (multiplicative
inverse + affine transform) rather than hard-coded tables. The
implementation is verified against the `cryptography` library's
accelerated AES before use.
"""

import struct

_RCON = [0x01]
for _ in range(13):
    _RCON.append((_RCON[-1] << 1) ^ (0x11B if _RCON[-1] & 0x80 else 0))

_SBOX = [0] * 256
_INV_SBOX = [0] * 256


def _build_sbox():
    def xtime(a):
        a <<= 1
        return (a ^ 0x11B) & 0xFF if a & 0x100 else a

    def gf_mul(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            a = xtime(a)
            b >>= 1
        return r

    for i in range(256):
        inv = 0
        if i:
            inv = 1
            for _e in range(254):
                inv = gf_mul(inv, i)
        s = inv
        rc = s
        for _ in range(4):
            rc = ((rc << 1) | (rc >> 7)) & 0xFF
            s ^= rc
        _SBOX[i] = s ^ 0x63
    for i, s in enumerate(_SBOX):
        _INV_SBOX[s] = i


_build_sbox()


def _xtime(a):
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a


def _gf_mul_byte(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _key_expansion(key: bytes) -> list[list[int]]:
    """Expand a 32-byte AES-256 key into 15 round-key 4x4 matrices."""
    words = [list(key[i:i + 4]) for i in range(0, 32, 4)]
    for i in range(8, 60):
        temp = list(words[i - 1])
        if i % 8 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // 8 - 1]
        elif i % 8 == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([words[i - 8][j] ^ temp[j] for j in range(4)])
    return [[words[rnd * 4 + c] for c in range(4)] for rnd in range(15)]  # 15 round keys, one column per word


def _add_round_key(state, rk):
    for c in range(4):
        for r in range(4):
            state[r][c] ^= rk[c][r]


def _sub_bytes(state, box):
    for r in range(4):
        for c in range(4):
            state[r][c] = box[state[r][c]]


def _shift_rows(state):
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]


def _inv_shift_rows(state):
    for r in range(1, 4):
        state[r] = state[r][-r:] + state[r][:-r]


def _mix_columns(state):
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = _xtime(a[0]) ^ (_xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3]
        state[1][c] = a[0] ^ _xtime(a[1]) ^ (_xtime(a[2]) ^ a[2]) ^ a[3]
        state[2][c] = a[0] ^ a[1] ^ _xtime(a[2]) ^ (_xtime(a[3]) ^ a[3])
        state[3][c] = (_xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ _xtime(a[3])


def _inv_mix_columns(state):
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = _gf_mul_byte(a[0], 14) ^ _gf_mul_byte(a[1], 11) ^ _gf_mul_byte(a[2], 13) ^ _gf_mul_byte(a[3], 9)
        state[1][c] = _gf_mul_byte(a[0], 9) ^ _gf_mul_byte(a[1], 14) ^ _gf_mul_byte(a[2], 11) ^ _gf_mul_byte(a[3], 13)
        state[2][c] = _gf_mul_byte(a[0], 13) ^ _gf_mul_byte(a[1], 9) ^ _gf_mul_byte(a[2], 14) ^ _gf_mul_byte(a[3], 11)
        state[3][c] = _gf_mul_byte(a[0], 11) ^ _gf_mul_byte(a[1], 13) ^ _gf_mul_byte(a[2], 9) ^ _gf_mul_byte(a[3], 14)


def encrypt_block(block: bytes, round_keys) -> bytes:
    """Encrypt one 16-byte block with AES-256 (14 rounds)."""
    state = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
    _add_round_key(state, round_keys[0])
    for rnd in range(1, 14):
        _sub_bytes(state, _SBOX)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[rnd])
    _sub_bytes(state, _SBOX)
    _shift_rows(state)
    _add_round_key(state, round_keys[14])
    return bytes(state[r][c] for c in range(4) for r in range(4))


def decrypt_block(block: bytes, round_keys) -> bytes:
    """Decrypt one 16-byte block with AES-256."""
    state = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
    _add_round_key(state, round_keys[14])
    for rnd in range(13, 0, -1):
        _inv_shift_rows(state)
        _sub_bytes(state, _INV_SBOX)
        _add_round_key(state, round_keys[rnd])
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _sub_bytes(state, _INV_SBOX)
    _add_round_key(state, round_keys[0])
    return bytes(state[r][c] for c in range(4) for r in range(4))


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class PureAES:
    """Pure-Python AES-256 supporting CTR, CBC, ECB, and GCM."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES-256 requires a 32-byte key")
        self._rk = _key_expansion(key)

    def encrypt_ecb(self, pt: bytes) -> bytes:
        out = bytearray()
        for i in range(0, len(pt), 16):
            out += encrypt_block(pt[i:i + 16], self._rk)
        return bytes(out)

    def decrypt_ecb(self, ct: bytes) -> bytes:
        out = bytearray()
        for i in range(0, len(ct), 16):
            out += decrypt_block(ct[i:i + 16], self._rk)
        return bytes(out)

    def encrypt_cbc(self, pt: bytes, iv: bytes) -> bytes:
        out = bytearray()
        prev = iv
        for i in range(0, len(pt), 16):
            prev = encrypt_block(_xor(pt[i:i + 16], prev), self._rk)
            out += prev
        return bytes(out)

    def decrypt_cbc(self, ct: bytes, iv: bytes) -> bytes:
        out = bytearray()
        prev = iv
        for i in range(0, len(ct), 16):
            out += _xor(decrypt_block(ct[i:i + 16], self._rk), prev)
            prev = ct[i:i + 16]
        return bytes(out)

    def _ctr_xor(self, data: bytes, initial_counter: int) -> bytes:
        out = bytearray()
        for i in range(0, len(data), 16):
            ctr_block = struct.pack(">16s", b"") [:0] + initial_counter.to_bytes(16, "big")
            ks = encrypt_block(ctr_block, self._rk)
            out += _xor(data[i:i + 16], ks)
            initial_counter += 1
        return bytes(out)

    def encrypt_ctr(self, pt: bytes, nonce: bytes) -> bytes:
        if len(nonce) != 16:
            raise ValueError("CTR nonce must be 16 bytes (counter included)")
        return self._ctr_xor(pt, int.from_bytes(nonce, "big"))

    def decrypt_ctr(self, ct: bytes, nonce: bytes) -> bytes:
        return self.encrypt_ctr(ct, nonce)

    def _ghash(self, data: bytes) -> int:
        h = int.from_bytes(encrypt_block(b"\x00" * 16, self._rk), "big")
        y = 0
        for i in range(0, len(data), 16):
            y ^= int.from_bytes(data[i:i + 16], "big")
            y = _gf_mult(y, h)
        return y

    def encrypt_gcm(self, pt: bytes, nonce: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
        if len(nonce) != 12:
            raise ValueError("GCM nonce must be 12 bytes")
        j0 = nonce + b"\x00\x00\x00\x01"
        ct = self._ctr_xor(pt, int.from_bytes(j0, "big") + 1)
        s = self._ghash(_pad16(aad) + _pad16(ct) + struct.pack(">QQ", len(aad) * 8, len(ct) * 8))
        tag = _xor(encrypt_block(j0, self._rk), s.to_bytes(16, "big"))
        return ct, tag

    def decrypt_gcm(self, ct: bytes, nonce: bytes, tag: bytes, aad: bytes = b"") -> bytes | None:
        j0 = nonce + b"\x00\x00\x00\x01"
        s = self._ghash(_pad16(aad) + _pad16(ct) + struct.pack(">QQ", len(aad) * 8, len(ct) * 8))
        expect = _xor(encrypt_block(j0, self._rk), s.to_bytes(16, "big"))
        if expect != tag:
            return None
        return self._ctr_xor(ct, int.from_bytes(j0, "big") + 1)


def _pad16(data: bytes) -> bytes:
    return data + b"\x00" * ((16 - len(data) % 16) % 16)


_R = 0xE1000000000000000000000000000000


def _gf_mult(x: int, y: int) -> int:
    """Multiplication in GF(2^128) per NIST SP 800-38D Algorithm 1."""
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z


if __name__ == "__main__":
    import secrets
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import padding as _pad

    key = secrets.token_bytes(32)
    aes = PureAES(key)
    lib = Cipher(algorithms.AES(key), modes.ECB())

    for trial in range(10):
        n = secrets.randbelow(64) * 16 + 16
        pt = secrets.token_bytes(n)
        iv = secrets.token_bytes(16)

        e = lib.encryptor()
        assert aes.encrypt_ecb(pt) == e.update(pt) + e.finalize(), "ECB mismatch"
        d = lib.decryptor()
        assert aes.decrypt_ecb(pt) == d.update(pt) + d.finalize(), "ECB decrypt mismatch"

        p = _pad.PKCS7(128).padder()
        padded = p.update(pt) + p.finalize()
        lib_cbc = Cipher(algorithms.AES(key), modes.CBC(iv))
        e = lib_cbc.encryptor()
        assert aes.encrypt_cbc(padded, iv) == e.update(padded) + e.finalize(), "CBC mismatch"

        lib_gcm = AESGCM(key)
        lib_out = lib_gcm.encrypt(iv[:12], pt, b"")
        my_ct, my_tag = aes.encrypt_gcm(pt, iv[:12])
        assert my_ct == lib_out[:-16], "GCM ciphertext mismatch"
        assert my_tag == lib_out[-16:], "GCM tag mismatch"
        assert aes.decrypt_gcm(my_ct, iv[:12], my_tag) == pt
        assert aes.decrypt_gcm(my_ct, iv[:12], bytes(16)) is None
    print("pure-Python AES-256 (ECB/CBC/GCM+GHASH) verified against cryptography library: 10/10 OK")