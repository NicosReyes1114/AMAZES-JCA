"""Pure-Python ChaCha20-Poly1305 (RFC 8439) — a non-hardware-accelerated baseline.

No AES-NI, no C extensions: every operation is plain Python integer
arithmetic, putting it in the same performance class as AMAZES-JCA (which
is also pure-Python per-character). The implementation is verified against
the `cryptography` library's accelerated ChaCha20Poly1305 before use.
"""

import struct


def _quarter_round(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = ((s[d] ^ s[a]) << 16 | (s[d] ^ s[a]) >> 16) & 0xFFFFFFFF
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = ((s[b] ^ s[c]) << 12 | (s[b] ^ s[c]) >> 20) & 0xFFFFFFFF
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = ((s[d] ^ s[a]) << 8 | (s[d] ^ s[a]) >> 24) & 0xFFFFFFFF
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = ((s[b] ^ s[c]) << 7 | (s[b] ^ s[c]) >> 25) & 0xFFFFFFFF


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """One 64-byte ChaCha20 keystream block (RFC 8439 section 2.3)."""
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key))
    state += [counter]
    state += list(struct.unpack("<3I", nonce))
    working = state[:]
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)
    return struct.pack("<16I", *[(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)])


def chacha20_keystream(key: bytes, nonce: bytes, length: int, initial_counter: int = 1) -> bytes:
    """ChaCha20 keystream starting at ``initial_counter`` (1 for AEAD data)."""
    out = bytearray()
    counter = initial_counter
    while len(out) < length:
        out += chacha20_block(key, counter, nonce)
        counter += 1
    return bytes(out[:length])


def poly1305(key: bytes, msg: bytes) -> bytes:
    """Poly1305 one-time authenticator (RFC 8439 section 2.5)."""
    P = (1 << 130) - 5
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16] + b"\x01"
        acc = ((acc + int.from_bytes(block, "little")) * r) % P
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")


def pad16(data: bytes) -> bytes:
    return b"\x00" * ((16 - len(data) % 16) % 16)


def aead_chacha20_poly1305(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """AEAD_CHACHA20_POLY1305 encrypt (RFC 8439 section 2.8).

    Returns:
        ``(ciphertext, tag)``.
    """
    poly_key = chacha20_block(key, 0, nonce)[:32]
    ct = bytes(a ^ b for a, b in zip(plaintext, chacha20_keystream(key, nonce, len(plaintext))))
    mac_data = aad + pad16(aad) + ct + pad16(ct)
    mac_data += struct.pack("<QQ", len(aad), len(ct))
    return ct, poly1305(poly_key, mac_data)


def aead_decrypt(key: bytes, nonce: bytes, ct: bytes, tag: bytes, aad: bytes = b"") -> bytes | None:
    poly_key = chacha20_block(key, 0, nonce)[:32]
    mac_data = aad + pad16(aad) + ct + pad16(ct)
    mac_data += struct.pack("<QQ", len(aad), len(ct))
    if poly1305(poly_key, mac_data) != tag:
        return None
    return bytes(a ^ b for a, b in zip(ct, chacha20_keystream(key, nonce, len(ct))))


if __name__ == "__main__":
    import secrets
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    for _ in range(20):
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        pt = secrets.token_bytes(secrets.randbelow(200) + 1)
        aad = secrets.token_bytes(secrets.randbelow(30))

        lib_ct = ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
        lib_ct_body, lib_tag = lib_ct[:-16], lib_ct[-16:]
        my_ct, my_tag = aead_chacha20_poly1305(key, nonce, pt, aad)
        assert my_ct == lib_ct_body, "ciphertext mismatch vs library"
        assert my_tag == lib_tag, "tag mismatch vs library"
        assert aead_decrypt(key, nonce, my_ct, my_tag, aad) == pt
        assert aead_decrypt(key, nonce, my_ct, bytes(16), aad) is None
    print("pure-Python ChaCha20-Poly1305 verified against cryptography library: 20/20 OK")