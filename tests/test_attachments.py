"""
Attachment test suite: chunked stream encryption + vault integration.

Security claims under test:
  - round trip at every chunk boundary (empty, exact chunk, multi chunk)
  - per-chunk AEAD: any modified byte fails to decrypt
  - index binding: chunk reordering fails
  - final-flag binding: truncation fails
  - uuid binding: blobs cannot be swapped between attachments
  - file keys are wrapped by the vault root, with their own AAD domain
  - metadata (size + sha256) is cross-checked after decryption
  - removing entries/attachments cleans up blobs
"""

from __future__ import annotations

import io
import os
from pathlib import Path

import pytest

from aegis import crypto
from aegis.crypto import AegisError, FormatError, KEY_LEN, UUID_LEN
from aegis.vault import Vault

FAST = dict(opslimit=1, memlimit=8 * 1024 * 1024)
PW = "correct horse battery staple"
CHUNK = 1024  # small chunk size so boundaries are cheap to test


# ---------------------------------------------------------------------------
# Stream layer
# ---------------------------------------------------------------------------

def _seal(data: bytes):
    key = crypto.random_bytes(KEY_LEN)
    att_uuid = crypto.random_bytes(UUID_LEN)
    dst = io.BytesIO()
    size, digest = crypto.seal_stream(key, att_uuid, io.BytesIO(data), dst,
                                      chunk_size=CHUNK)
    return key, att_uuid, dst.getvalue(), size, digest


def _open(key: bytes, att_uuid: bytes, blob: bytes):
    dst = io.BytesIO()
    size, digest = crypto.open_stream(key, att_uuid, io.BytesIO(blob), dst,
                                      chunk_size=CHUNK)
    return dst.getvalue(), size, digest


def test_stream_roundtrip_at_chunk_boundaries():
    cases = [b"", b"x", b"A" * (CHUNK - 1), b"B" * CHUNK, b"C" * (CHUNK + 1),
             os.urandom(3 * CHUNK + 7)]
    for data in cases:
        key, att_uuid, blob, size, digest = _seal(data)
        got, got_size, got_digest = _open(key, att_uuid, blob)
        assert got == data
        assert got_size == size == len(data)
        assert got_digest == digest


def test_stream_tamper_any_byte_fails():
    key, att_uuid, blob, _, _ = _seal(os.urandom(2 * CHUNK + 5))
    positions = [crypto.ATT_HEADER_LEN, crypto.ATT_HEADER_LEN + 10,
                 len(blob) // 2, len(blob) - 1]
    for pos in positions:
        bad = bytearray(blob)
        bad[pos] ^= 0x01
        with pytest.raises(FormatError):
            _open(key, att_uuid, bytes(bad))


def test_stream_truncation_fails():
    data = os.urandom(3 * CHUNK)  # exactly three full chunks
    key, att_uuid, blob, _, _ = _seal(data)

    # Map the three chunk records to prove the cut point is real.
    offset = crypto.ATT_HEADER_LEN
    record_starts = []
    for _ in range(3):
        record_starts.append(offset)
        length = int.from_bytes(blob[offset + 24:offset + 28], "little")
        offset += 28 + length + 16
    assert offset == len(blob)

    # Dropping the final record must fail (final-flag AAD mismatch) ...
    with pytest.raises(FormatError):
        _open(key, att_uuid, blob[:record_starts[2]])
    # ... and so must a partial final record.
    with pytest.raises(FormatError):
        _open(key, att_uuid, blob[:-5])


def test_stream_reorder_fails():
    key, att_uuid, blob, _, _ = _seal(b"A" * CHUNK + b"B" * 11)
    first = (crypto.ATT_HEADER_LEN, CHUNK + 44)   # record 0: 24+4+CHUNK+16
    second_start = first[0] + first[1]
    swapped = (blob[:first[0]]
               + blob[second_start:]
               + blob[first[0]:second_start])
    with pytest.raises(FormatError):
        _open(key, att_uuid, swapped)


def test_stream_uuid_binding_fails():
    key1, uuid1, blob1, _, _ = _seal(b"one" * 100)
    key2, uuid2, blob2, _, _ = _seal(b"two" * 100)
    with pytest.raises(FormatError):
        _open(key2, uuid2, blob1)   # header uuid mismatch
    with pytest.raises(FormatError):
        _open(key1, uuid1, blob2)


def test_wrap_unwrap_roundtrip_and_domains():
    root = crypto.random_bytes(32)
    vault_uuid = crypto.random_bytes(16)
    att_uuid = crypto.random_bytes(16)
    file_key = crypto.random_bytes(32)

    wrapped = crypto.wrap_file_key(root, vault_uuid, att_uuid, file_key)
    assert crypto.unwrap_file_key(root, vault_uuid, att_uuid, wrapped) == file_key

    with pytest.raises(FormatError):
        crypto.unwrap_file_key(os.urandom(32), vault_uuid, att_uuid, wrapped)
    with pytest.raises(FormatError):
        crypto.unwrap_file_key(root, crypto.random_bytes(16), att_uuid, wrapped)
    with pytest.raises(FormatError):
        crypto.unwrap_file_key(root, vault_uuid, crypto.random_bytes(16),
                               wrapped)


# ---------------------------------------------------------------------------
# Vault integration
# ---------------------------------------------------------------------------

def _make_vault(tmp_path: Path) -> Vault:
    vault = Vault.create(tmp_path / "v.ags", PW, **FAST)
    vault.add_entry("docs", kind="note", notes="scans")
    return vault


def test_attach_extract_roundtrip(tmp_path: Path):
    vault = _make_vault(tmp_path)
    data = b"TOPSECRET-" + os.urandom(200_000)
    meta = vault.attach_file("docs", io.BytesIO(data), "scan.bin")

    assert meta["size"] == len(data)
    assert meta["name"] == "scan.bin"
    assert vault.get_attachment("docs", meta["id"][:8])["id"] == meta["id"]

    out = io.BytesIO()
    vault.open_attachment("docs", meta["id"], out)
    assert out.getvalue() == data

    blob = (vault.attachments_dir / f"{meta['id']}.bin").read_bytes()
    assert b"TOPSECRET-" not in blob  # ciphertext, not plaintext, on disk


def test_attachment_persists_across_reload(tmp_path: Path):
    vault = _make_vault(tmp_path)
    data = b"persist me " * 1000
    meta = vault.attach_file("docs", io.BytesIO(data), "p.txt")
    vault.lock()

    vault2 = Vault.load(tmp_path / "v.ags", PW)
    out = io.BytesIO()
    vault2.open_attachment("docs", meta["id"], out)
    assert out.getvalue() == data


def test_attachment_metadata_is_cross_checked(tmp_path: Path):
    vault = _make_vault(tmp_path)
    meta = vault.attach_file("docs", io.BytesIO(b"data" * 500), "d.bin")
    entry = vault._entries[vault._resolve("docs")]
    entry["attachments"][0]["sha256"] = "0" * 64  # forge the stored hash
    with pytest.raises(AegisError):
        vault.open_attachment("docs", meta["id"], io.BytesIO())


def test_swapped_blobs_through_vault_fail(tmp_path: Path):
    vault = _make_vault(tmp_path)
    m1 = vault.attach_file("docs", io.BytesIO(b"first" * 300), "1.bin")
    m2 = vault.attach_file("docs", io.BytesIO(b"second" * 300), "2.bin")
    src = vault.attachments_dir / f"{m1['id']}.bin"
    dst = vault.attachments_dir / f"{m2['id']}.bin"
    dst.write_bytes(src.read_bytes())
    with pytest.raises(AegisError):
        vault.open_attachment("docs", m2["id"], io.BytesIO())


def test_removal_cleans_up_blobs(tmp_path: Path):
    vault = _make_vault(tmp_path)
    m1 = vault.attach_file("docs", io.BytesIO(b"a" * 100), "a.bin")
    m2 = vault.attach_file("docs", io.BytesIO(b"b" * 100), "b.bin")

    vault.remove_attachment("docs", m1["id"])
    assert not (vault.attachments_dir / f"{m1['id']}.bin").exists()
    assert vault.get_entry("docs")["attachments"][0]["id"] == m2["id"]

    vault.remove_entry("docs")
    assert not (vault.attachments_dir / f"{m2['id']}.bin").exists()


def test_attachment_names_are_sanitized(tmp_path: Path):
    vault = _make_vault(tmp_path)
    with pytest.raises(AegisError):
        vault.attach_file("docs", io.BytesIO(b"x"), "")
    with pytest.raises(AegisError):
        vault.attach_file("docs", io.BytesIO(b"x"), "bad\nname.bin")
    meta = vault.attach_file("docs", io.BytesIO(b"x"), "dir/file.bin")
    assert meta["name"] == "dir_file.bin"


def test_open_missing_blob_fails_kindly(tmp_path: Path):
    vault = _make_vault(tmp_path)
    meta = vault.attach_file("docs", io.BytesIO(b"z" * 50), "z.bin")
    (vault.attachments_dir / f"{meta['id']}.bin").unlink()
    with pytest.raises(AegisError):
        vault.open_attachment("docs", meta["id"], io.BytesIO())


def test_truncated_upload_rejected(tmp_path: Path):
    """A client that dies mid-upload must not register a file whose
    plaintext size does not match what it promised."""
    vault = _make_vault(tmp_path)
    with pytest.raises(AegisError):
        vault.attach_file("docs", io.BytesIO(b"only-a-little"),
                          "big.bin", expected_size=10_000)
    assert not vault.get_entry("docs").get("attachments")
