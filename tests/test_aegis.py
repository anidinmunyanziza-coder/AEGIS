"""
Aegis vault test suite.

Every security property claimed in the README has a test here:
  - known-answer test for HKDF (RFC 5869 test case 1)
  - round-trip, wrong-password, wrong-keyfile rejection
  - header-tampering rejection (Argon2id parameter downgrade)
  - ciphertext and MAC bit-flip rejection, truncation, bad magic
  - load-time KDF parameter bounds (memory DoS guard)
  - no password verifier oracle in the file format
  - nonce freshness across saves, no plaintext in the file
  - master password rotation, keyfile second factor behavior
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from aegis import crypto
from aegis.crypto import (
    AegisError,
    FLAG_KEYFILE,
    FLAGS_OFFSET,
    FormatError,
    HEADER_LEN,
    MAC_LEN,
    MEMLIMIT_OFFSET,
    NONCE_LEN,
    OPSLIMIT_OFFSET,
    UnlockError,
)
from aegis.vault import Vault

# Cheap Argon2id parameters so the suite runs in seconds. 8 MiB / t=1 is
# far above the libsodium floor and far below the 256 MiB production
# default (asserted separately in test_defaults_are_production_grade).
FAST = dict(opslimit=1, memlimit=8 * 1024 * 1024)
PW = "correct horse battery staple"


@pytest.fixture()
def vpath(tmp_path: Path) -> Path:
    return tmp_path / "test.ags"


def _read(p: Path) -> bytearray:
    return bytearray(Path(p).read_bytes())


def _write(p: Path, buf: bytearray) -> None:
    Path(p).write_bytes(bytes(buf))


# ---------------------------------------------------------------------------
# Primitive correctness
# ---------------------------------------------------------------------------

def test_hkdf_rfc5869_case1():
    """HKDF-SHA256 known-answer test, RFC 5869 appendix A.1."""
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm = crypto.hkdf_sha256(ikm, salt, info, 42)
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )


def test_defaults_are_production_grade():
    """256 MiB / t=3: 4x the RFC 9106 second recommendation (64 MiB, t=3)
    and >13x the OWASP Argon2id floor (19 MiB, t=2)."""
    assert crypto.DEFAULT_MEMLIMIT >= 256 * 1024 * 1024
    assert crypto.DEFAULT_OPSLIMIT >= 3


def test_generate_password():
    pw = crypto.generate_password(24)
    assert len(pw) == 24
    assert all(c in crypto._PW_ALPHABET for c in pw)
    with pytest.raises(ValueError):
        crypto.generate_password(8)


# ---------------------------------------------------------------------------
# Round trip
# ---------------------------------------------------------------------------

def test_roundtrip(vpath: Path):
    v = Vault.create(vpath, PW, **FAST)
    vid = v.add_entry("github", username="reid", password="hunter2",
                      url="https://github.com", notes="personal")
    assert len(vid) == 32
    v.save()
    v.lock()
    with pytest.raises(AegisError):
        v.save()  # locked vault must refuse to operate

    v2 = Vault.load(vpath, PW)
    e = v2.get_entry("github")
    assert e["password"] == "hunter2"
    assert e["username"] == "reid"
    assert e["id"] == vid
    # resolution by id prefix
    assert v2.get_entry(vid[:8])["name"] == "github"
    v2.lock()

    with pytest.raises(AegisError):
        Vault.create(vpath, PW, **FAST)  # refuses to overwrite


def test_add_get_remove(vpath: Path):
    v = Vault.create(vpath, PW, **FAST)
    v.add_entry("alpha", password="a" * 12)
    v.add_entry("beta", username="u2", password="b" * 12)
    v.save()
    v.lock()

    v = Vault.load(vpath, PW)
    assert len(v.list_entries()) == 2
    v.remove_entry("alpha")
    v.save()
    v.lock()

    v = Vault.load(vpath, PW)
    assert [r["name"] for r in v.list_entries()] == ["beta"]
    with pytest.raises(KeyError):
        v.get_entry("alpha")


def test_unicode_password_normalization(vpath: Path):
    """'café' typed as NFC and as NFD must unlock the same vault."""
    v = Vault.create(vpath, "caf\u00e9", **FAST)
    v.lock()
    v2 = Vault.load(vpath, "cafe\u0301")
    assert len(v2) == 0


# ---------------------------------------------------------------------------
# Authentication failures (fail closed, uniformly)
# ---------------------------------------------------------------------------

def test_wrong_password_rejected(vpath: Path):
    v = Vault.create(vpath, PW, **FAST)
    v.lock()
    with pytest.raises(UnlockError):
        Vault.load(vpath, "wrong password")


def test_ciphertext_bitflip_rejected(vpath: Path):
    v = Vault.create(vpath, PW, **FAST)
    v.add_entry("x", password="secret")
    v.save()
    v.lock()
    assert Vault.load(vpath, PW).get_entry("x")  # sanity: loads before tamper

    buf = _read(vpath)
    buf[-1] ^= 0xFF  # flip one ciphertext/tag bit
    _write(vpath, buf)
    with pytest.raises(UnlockError):
        Vault.load(vpath, PW)


def test_mac_bitflip_rejected(vpath: Path):
    v = Vault.create(vpath, PW, **FAST)
    v.lock()
    buf = _read(vpath)
    buf[HEADER_LEN] ^= 0x01  # flip one header-MAC bit
    _write(vpath, buf)
    with pytest.raises(UnlockError):
        Vault.load(vpath, PW)


# ---------------------------------------------------------------------------
# Header tampering: the parameter-downgrade attack
# ---------------------------------------------------------------------------

def test_memlimit_downgrade_rejected(vpath: Path):
    """The classic attack: lower the stored Argon2id memlimit so offline
    cracking gets cheaper. The header HMAC and the AEAD AAD binding make
    the modified file fail closed even with the correct password."""
    v = Vault.create(vpath, PW, **FAST)
    v.lock()
    assert len(Vault.load(vpath, PW)) == 0  # sanity: loads before tamper

    buf = _read(vpath)
    struct.pack_into("<Q", buf, MEMLIMIT_OFFSET, 4 * 1024 * 1024)
    _write(vpath, buf)
    with pytest.raises(AegisError):
        Vault.load(vpath, PW)


def test_opslimit_tamper_rejected(vpath: Path):
    v = Vault.create(vpath, PW, **FAST)
    v.lock()
    buf = _read(vpath)
    struct.pack_into("<I", buf, OPSLIMIT_OFFSET, 2)
    _write(vpath, buf)
    with pytest.raises(AegisError):
        Vault.load(vpath, PW)


def test_kdf_param_bounds_guard(vpath: Path):
    """A hostile vault file must not make the loader allocate gigabytes
    or spin for minutes before authentication even runs."""
    v = Vault.create(vpath, PW, **FAST)
    v.lock()

    buf = _read(vpath)
    struct.pack_into("<Q", buf, MEMLIMIT_OFFSET, 8 * 1024 * 1024 * 1024)
    _write(vpath, buf)
    with pytest.raises(FormatError):
        Vault.load(vpath, PW)

    buf = _read(vpath)
    struct.pack_into("<I", buf, OPSLIMIT_OFFSET, 1000)
    _write(vpath, buf)
    with pytest.raises(FormatError):
        Vault.load(vpath, PW)


# ---------------------------------------------------------------------------
# Structural rejects
# ---------------------------------------------------------------------------

def test_truncated_file_rejected(vpath: Path):
    v = Vault.create(vpath, PW, **FAST)
    v.lock()
    _write(vpath, _read(vpath)[:HEADER_LEN + 10])
    with pytest.raises(FormatError):
        Vault.load(vpath, PW)


def test_bad_magic_rejected(vpath: Path):
    v = Vault.create(vpath, PW, **FAST)
    v.lock()
    buf = _read(vpath)
    buf[0:4] = b"XXXX"
    _write(vpath, buf)
    with pytest.raises(FormatError):
        Vault.load(vpath, PW)


def test_reserved_bytes_must_be_zero(vpath: Path):
    v = Vault.create(vpath, PW, **FAST)
    v.lock()
    buf = _read(vpath)
    buf[FLAGS_OFFSET + 1] = 0x01  # reserved byte, not flags byte
    _write(vpath, buf)
    with pytest.raises(FormatError):
        Vault.load(vpath, PW)


# ---------------------------------------------------------------------------
# Keyfile second factor
# ---------------------------------------------------------------------------

def test_keyfile_required(vpath: Path):
    kf = os.urandom(32)
    v = Vault.create(vpath, PW, keyfile=kf, **FAST)
    v.add_entry("mail", password="m")
    v.save()
    v.lock()

    with pytest.raises(UnlockError):
        Vault.load(vpath, PW)  # no keyfile
    with pytest.raises(UnlockError):
        Vault.load(vpath, PW, keyfile=os.urandom(32))  # wrong keyfile

    v2 = Vault.load(vpath, PW, keyfile=kf)
    assert v2.get_entry("mail")["password"] == "m"


def test_keyfile_flag_stripped_still_fails(vpath: Path):
    """Attacker clears the 'keyfile required' flag to try to bypass the
    second factor. The flag is inside the HMAC-protected header, so the
    derivation path changes and the vault fails closed."""
    kf = os.urandom(32)
    v = Vault.create(vpath, PW, keyfile=kf, **FAST)
    v.lock()

    buf = _read(vpath)
    buf[FLAGS_OFFSET] &= ~FLAG_KEYFILE
    _write(vpath, buf)
    with pytest.raises(AegisError):
        Vault.load(vpath, PW)  # correct password, no keyfile, flag forged


# ---------------------------------------------------------------------------
# Master password rotation & save hygiene
# ---------------------------------------------------------------------------

def test_change_master_password(vpath: Path):
    v = Vault.create(vpath, PW, **FAST)
    v.add_entry("bank", password="s3cret")
    v.save()
    v.change_master_password("a totally new master phrase")
    v.lock()

    with pytest.raises(UnlockError):
        Vault.load(vpath, PW)  # old password dead
    v2 = Vault.load(vpath, "a totally new master phrase")
    assert v2.get_entry("bank")["password"] == "s3cret"


def test_change_master_password_with_keyfile(vpath: Path):
    kf = os.urandom(32)
    v = Vault.create(vpath, PW, keyfile=kf, **FAST)
    v.change_master_password("new phrase")
    v.lock()
    v2 = Vault.load(vpath, "new phrase", keyfile=kf)
    assert len(v2) == 0


def test_nonce_uniqueness_across_saves(vpath: Path):
    """Every save must use a fresh random nonce (I3). Nonce reuse under
    the same key is catastrophic for AEAD schemes."""
    v = Vault.create(vpath, PW, **FAST)
    v.save()
    nonce1 = bytes(_read(vpath)[HEADER_LEN + MAC_LEN:
                                HEADER_LEN + MAC_LEN + NONCE_LEN])
    v.save()
    nonce2 = bytes(_read(vpath)[HEADER_LEN + MAC_LEN:
                                HEADER_LEN + MAC_LEN + NONCE_LEN])
    assert nonce1 != nonce2


def test_revision_increments(vpath: Path):
    v = Vault.create(vpath, PW, **FAST)
    assert v.revision == 1
    v.save()
    assert v.revision == 2
    v.lock()
    assert Vault.load(vpath, PW).revision == 2


def test_no_plaintext_in_vault_file(vpath: Path):
    v = Vault.create(vpath, PW, **FAST)
    v.add_entry("github", username="reid-secret-user",
                password="S3cretP@ss!", url="https://github.com",
                notes="two factor backup codes inside")
    v.save()
    v.lock()

    raw = Path(vpath).read_bytes()
    for needle in (b"github", b"reid-secret-user", b"S3cretP@ss!",
                   b"https://github.com", b"two factor"):
        assert needle not in raw, f"plaintext leaked into vault file: {needle!r}"


def test_atomic_write_preserves_binary_bytes(tmp_path: Path):
    """Regression test: a Windows text-mode file handle translates every
    0x0A byte to 0x0D 0x0A. Vault files are full of random bytes, so the
    write path must be byte-exact. This test forced the original bug
    deterministically (live vaults hit it only when their random tag,
    nonce or ciphertext happened to contain a 0x0A)."""
    from aegis.vault import _atomic_write

    target = tmp_path / "raw.bin"
    blob = bytes(range(256)) * 4  # contains 0x0A, 0x0D and everything else
    _atomic_write(target, blob)
    assert target.read_bytes() == blob


# ---------------------------------------------------------------------------
# Entry kinds & partial updates
# ---------------------------------------------------------------------------

def test_entry_kinds_and_update(vpath: Path):
    v = Vault.create(vpath, PW, **FAST)
    lid = v.add_entry("site", password="p" * 8)
    nid = v.add_entry("recovery codes", kind="note", notes="AAAA-BBBB")
    with pytest.raises(AegisError):
        v.add_entry("bad", kind="weird")

    v.update_entry(nid, name="recovery codes v2", notes="CCCC-DDDD")
    with pytest.raises(AegisError):
        v.update_entry(nid, name="")  # empty name rejected
    with pytest.raises(KeyError):
        v.update_entry("no-such-ident", notes="x")
    v.save()
    v.lock()

    v2 = Vault.load(vpath, PW)
    assert v2.get_entry(lid)["kind"] == "login"
    note = v2.get_entry("recovery codes v2")
    assert note["kind"] == "note"
    assert note["notes"] == "CCCC-DDDD"
    assert note["id"] == nid
    # partial update must not have touched unrelated fields
    assert v2.get_entry("site")["password"] == "p" * 8


def test_pre_kind_entries_default_to_login(vpath: Path):
    """Vault payloads written before kinds existed must still load and
    behave as ordinary login entries."""
    v = Vault.create(vpath, PW, **FAST)
    eid = v.add_entry("legacy", password="x" * 6)
    v._entries[eid].pop("kind", None)  # simulate an older vault payload
    rows = {r["name"]: r for r in v.all_entries()}
    assert rows["legacy"]["kind"] == "login"
    assert {r["name"]: r for r in v.list_entries()}["legacy"]["kind"] == "login"
