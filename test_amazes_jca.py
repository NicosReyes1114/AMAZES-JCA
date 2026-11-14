"""Test suite for AMAZES-JCA (Full-Hardened).

Runs standalone with only the standard library:

    python test_amazes_jca.py

or under pytest:

    pytest test_amazes_jca.py
"""

from __future__ import annotations

import AMAZES_JCA as aj

TESTS = []


def _register(fn, name: str) -> None:
    fn.__name__ = name
    fn.__qualname__ = name
    globals()[name] = fn
    TESTS.append(fn)


def make_creds() -> tuple[str, list[int]]:
    seed, key_str = aj.generate_session_credentials()
    return seed, aj.parse_key_string(key_str)


def _expect_value_error(fn, *args) -> None:
    try:
        fn(*args)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# --- Roundtrip matrix (5 cases) ---

ROUNDTRIP_MESSAGES = [
    "Hello, World!",
    "",
    "A" * 200,
    "The quick brown fox jumps over the lazy dog 0123456789",
    " ~!@#$%^&*()_+`-=[]\\;',./{}|:<>?",
]


def _make_roundtrip(msg: str):
    def test():
        seed, key = make_creds()
        package, _ = aj.run_amazes(msg, seed, key, encrypt=True)
        assert len(package) == len(msg) + aj.SALT_SIZE + aj.TAG_SIZE
        pt, valid = aj.run_amazes(package, seed, key, encrypt=False)
        assert valid, "JCA tag did not verify"
        assert pt == msg
    return test


for _i, _msg in enumerate(ROUNDTRIP_MESSAGES):
    _register(_make_roundtrip(_msg), f"test_roundtrip_case_{_i}")


# --- Credential sensitivity ---

def test_same_key_different_seeds_differ():
    msg = "same message"
    packages = set()
    for _ in range(5):
        seed, key = make_creds()
        packages.add(aj.run_amazes(msg, seed, key, encrypt=True)[0])
    assert len(packages) == 5


def test_fresh_salt_randomizes_output():
    seed, key = make_creds()
    c1, _ = aj.run_amazes("same message", seed, key, encrypt=True)
    c2, _ = aj.run_amazes("same message", seed, key, encrypt=True)
    assert c1 != c2


def test_wrong_key_rejected():
    seed, key = make_creds()
    _, wrong_key = make_creds()
    package, _ = aj.run_amazes("secret", seed, key, encrypt=True)
    pt, valid = aj.run_amazes(package, seed, wrong_key, encrypt=False)
    assert not valid and pt is None


def test_wrong_seed_rejected():
    seed, key = make_creds()
    wrong_seed, _ = make_creds()
    package, _ = aj.run_amazes("secret", seed, key, encrypt=True)
    pt, valid = aj.run_amazes(package, wrong_seed, key, encrypt=False)
    assert not valid and pt is None


# --- Tamper matrix (6 cases) ---

TAMPER_VECTORS = ["flip", "swap", "truncate", "salt_flip", "tag_flip", "splice"]


def _make_tamper(tamper: str):
    def test():
        seed, key = make_creds()
        package, _ = aj.run_amazes("attack at dawn", seed, key, encrypt=True)
        body_mid = aj.SALT_SIZE + (len(package) - aj.SALT_SIZE - aj.TAG_SIZE) // 2
        if tamper == "flip":
            c = package[body_mid]
            package = package[:body_mid] + chr((ord(c) - 32 + 1) % 95 + 32) + package[body_mid + 1:]
        elif tamper == "swap":
            package = package[:body_mid] + package[body_mid + 1] + package[body_mid] + package[body_mid + 2:]
        elif tamper == "truncate":
            package = package[:-1]
        elif tamper == "salt_flip":
            repl = "A" if package[0] != "A" else "B"
            package = repl + package[1:]
        elif tamper == "tag_flip":
            last = package[-1]
            repl = "0" if last != "0" else "1"
            package = package[:-1] + repl
        elif tamper == "splice":
            other, _ = aj.run_amazes("other message entirely", seed, key, encrypt=True)
            package = package[:body_mid] + other[body_mid:-aj.TAG_SIZE] + package[-aj.TAG_SIZE:]
        pt, valid = aj.run_amazes(package, seed, key, encrypt=False)
        assert not valid and pt is None
    return test


for _vec in TAMPER_VECTORS:
    _register(_make_tamper(_vec), f"test_tamper_{_vec}")


# --- Input validation (5 cases) ---

BAD_CHARS = ["\n", "\t", "é", "你好", "\x00"]


def _make_bad_char(bad_char: str):
    def test():
        seed, key = make_creds()
        _expect_value_error(aj.run_amazes, "bad" + bad_char + "input", seed, key, True)
    return test


for _i, _c in enumerate(BAD_CHARS):
    _register(_make_bad_char(_c), f"test_non_charset_rejected_{_i}")


# --- Structural validation ---

def test_short_package_rejected():
    seed, key = make_creds()
    _expect_value_error(aj.run_amazes, "short", seed, key, False)


def test_invalid_key_rejected():
    _expect_value_error(aj.parse_key_string, "not-hex!")
    _expect_value_error(aj.parse_key_string, "")


def test_bad_salt_length_rejected():
    seed, key = make_creds()
    _expect_value_error(aj.AmazesEngine, list(range(aj.ROTOR_SIZE)), key, "short", seed)


# --- Diffusion ---

def test_diffusion_same_salt_single_char_change():
    seed, key = make_creds()
    c1 = aj.run_amazes("A" * 40, seed, key, encrypt=True, salt="ZZ9Qx7#K")[0][aj.SALT_SIZE:-aj.TAG_SIZE]
    c2 = aj.run_amazes("A" * 39 + "B", seed, key, encrypt=True, salt="ZZ9Qx7#K")[0][aj.SALT_SIZE:-aj.TAG_SIZE]
    diff = sum(a != b for a, b in zip(c1, c2))
    assert diff == 1


TESTS += [
    test_same_key_different_seeds_differ,
    test_fresh_salt_randomizes_output,
    test_wrong_key_rejected,
    test_wrong_seed_rejected,
    test_short_package_rejected,
    test_invalid_key_rejected,
    test_bad_salt_length_rejected,
    test_diffusion_same_salt_single_char_change,
]


# --- Standalone runner ---

def main() -> None:
    passed = 0
    failures = []
    for t in TESTS:
        try:
            t()
            print(f"PASS  {t.__name__}")
            passed += 1
        except AssertionError as exc:
            print(f"FAIL  {t.__name__}: {exc or 'assertion failed'}")
            failures.append(t.__name__)
        except Exception as exc:
            print(f"ERROR {t.__name__}: {exc!r}")
            failures.append(t.__name__)
    print(f"\n{passed}/{len(TESTS)} tests passed")
    if failures:
        print("failed: " + ", ".join(failures))
        raise SystemExit(1)


if __name__ == "__main__":
    main()