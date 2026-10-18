"""
Aegis vault: the document layer.

Holds decrypted entries in memory while unlocked, serializes them to JSON,
and hands the bytes to crypto.seal_payload() for sealing. Files are written
atomically (temp file + fsync + rename) so a crash mid-save can never leave
a half-written vault behind.
"""

from __future__ import annotations

import base64
import json
import os
import time
import uuid
from dataclasses import replace
from pathlib import Path

from . import crypto
from .crypto import (
    AegisError,
    DEFAULT_MEMLIMIT,
    DEFAULT_OPSLIMIT,
    FormatError,
    Header,
    SALT_LEN,
    UnlockError,
)

PAYLOAD_FORMAT = "aegis.vault/1"

# Entry kinds the vault can hold. Extensible: add "card", "wifi", ...
KINDS = ("login", "note")

KEYFILE_BYTES = 32
KEYFILE_MIN_BYTES = 16


def _now() -> int:
    return int(time.time())


# ---------------------------------------------------------------------------
# Keyfile helpers (second factor)
# ---------------------------------------------------------------------------

def generate_keyfile(path: str | Path) -> Path:
    """Write a fresh 32-byte random keyfile. Refuses to overwrite."""
    path = Path(path)
    if path.exists():
        raise AegisError(f"refusing to overwrite existing file {path}")
    path.write_bytes(crypto.random_bytes(KEYFILE_BYTES))
    return path


def read_keyfile(path: str | Path) -> bytes:
    data = Path(path).read_bytes()
    if len(data) < KEYFILE_MIN_BYTES:
        raise AegisError("keyfile too short (need at least 16 bytes)")
    return data


# ---------------------------------------------------------------------------
# Atomic write
# ---------------------------------------------------------------------------

def _atomic_write(path: Path, data: bytes) -> None:
    """Write to a temp file, fsync, then atomically replace the target.

    The file is opened with Python's builtin binary mode. Do NOT replace
    this with os.open() flags: on Windows, os.open without O_BINARY opens
    in text mode and every 0x0A byte in the random tag/nonce/ciphertext
    gets silently expanded to 0x0D 0x0A, corrupting the vault. That bug
    is why tests/test_aegis.py has a byte-for-byte regression test.
    """
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    if os.name == "posix":
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------

class Vault:
    """An unlocked vault. Holds decrypted entries and live key material.

    Key material policy: only the 32-byte root key lives in memory, and it
    is zeroized on lock(). Encryption and MAC subkeys are derived per
    operation and wiped immediately (see crypto.subkeys).
    """

    def __init__(self, path: Path, header: Header, root: bytearray,
                 entries: dict[str, dict], created_at: int,
                 keyfile: bytes | None = None) -> None:
        self._path = Path(path)
        self._header = header
        self._root = root
        self._entries: dict[str, dict] = entries
        self._created_at = created_at
        self._keyfile = keyfile
        self._locked = False

    # -- lifecycle ----------------------------------------------------------

    @classmethod
    def create(cls, path: str | Path, password: str, *,
               keyfile: bytes | None = None,
               opslimit: int = DEFAULT_OPSLIMIT,
               memlimit: int = DEFAULT_MEMLIMIT) -> "Vault":
        """Create a new, empty vault and write it to disk."""
        path = Path(path)
        if path.exists():
            raise AegisError(f"refusing to overwrite existing vault {path}")
        if not (crypto.MIN_OPSLIMIT <= opslimit <= crypto.MAX_OPSLIMIT):
            raise AegisError("opslimit out of range")
        if not (crypto.MIN_MEMLIMIT <= memlimit <= crypto.MAX_MEMLIMIT):
            raise AegisError("memlimit out of range")

        salt = crypto.random_bytes(SALT_LEN)
        root = crypto.derive_root(password, salt, opslimit, memlimit, keyfile)
        header = Header(
            version=crypto.FORMAT_VERSION,
            kdf_id=crypto.KDF_ID_ARGON2ID,
            opslimit=opslimit,
            memlimit=memlimit,
            salt=salt,
            keyfile_required=keyfile is not None,
            vault_uuid=crypto.random_bytes(crypto.UUID_LEN),
            created_at=_now(),
            revision=0,
        )
        vault = cls(path, header, root, {}, header.created_at, keyfile=keyfile)
        vault.save()
        return vault

    @classmethod
    def load(cls, path: str | Path, password: str, *,
             keyfile: bytes | None = None) -> "Vault":
        """Open an existing vault. Raises UnlockError if the password, the
        keyfile, or the file itself is not exactly right."""
        path = Path(path)
        data = path.read_bytes()
        header_raw, header, tag, nonce, ciphertext = crypto.parse_file(data)

        if header.keyfile_required and keyfile is None:
            raise UnlockError("this vault requires a keyfile")
        used_keyfile = keyfile if header.keyfile_required else None

        root = crypto.derive_root(password, header.salt, header.opslimit,
                                  header.memlimit, used_keyfile)
        try:
            plaintext = crypto.open_payload(root, header_raw, tag, nonce,
                                            ciphertext)
        except AegisError:
            crypto.zeroize(root)
            raise

        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            crypto.zeroize(root)
            raise FormatError("decrypted payload is not valid JSON") from exc
        if not isinstance(payload, dict) or payload.get("format") != PAYLOAD_FORMAT:
            crypto.zeroize(root)
            raise FormatError("unexpected payload format")
        entries = payload.get("entries")
        if not isinstance(entries, dict):
            crypto.zeroize(root)
            raise FormatError("payload entries are malformed")

        return cls(path, header, root, entries,
                   payload.get("created", header.created_at),
                   keyfile=used_keyfile)

    def lock(self) -> None:
        """Drop key material. The instance is unusable afterwards."""
        if self._root is not None:
            crypto.zeroize(self._root)
        if self._keyfile is not None:
            scratch = bytearray(self._keyfile)
            crypto.zeroize(scratch)
        self._locked = True

    def _assert_unlocked(self) -> None:
        if self._locked:
            raise AegisError("vault is locked")

    # -- persistence ---------------------------------------------------------

    @property
    def path(self) -> Path:
        return self._path

    @property
    def revision(self) -> int:
        return self._header.revision

    @property
    def uses_keyfile(self) -> bool:
        return self._header.keyfile_required

    def save(self) -> None:
        """Re-seal the whole vault with a fresh nonce and write atomically."""
        self._assert_unlocked()
        self._header = self._header.bumped()
        payload = json.dumps(
            {
                "format": PAYLOAD_FORMAT,
                "created": self._created_at,
                "entries": self._entries,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        sealed = crypto.seal_payload(self._root, self._header, payload)
        _atomic_write(self._path, sealed)

    def change_master_password(self, new_password: str) -> None:
        """Rotate the master password: new salt, new root key, re-seal."""
        self._assert_unlocked()
        new_salt = crypto.random_bytes(SALT_LEN)
        new_root = crypto.derive_root(new_password, new_salt,
                                      self._header.opslimit,
                                      self._header.memlimit,
                                      self._keyfile)
        crypto.zeroize(self._root)
        self._root = new_root
        self._header = replace(self._header, salt=new_salt)
        self.save()

    # -- entries -------------------------------------------------------------

    def add_entry(self, name: str, *, kind: str = "login",
                  username: str = "", password: str = "",
                  url: str = "", notes: str = "") -> str:
        """Add an entry; returns its id."""
        self._assert_unlocked()
        if not name:
            raise AegisError("entry name must not be empty")
        if kind not in KINDS:
            raise AegisError(f"unknown entry kind {kind!r}")
        entry_id = uuid.uuid4().hex
        now = _now()
        self._entries[entry_id] = {
            "kind": kind,
            "name": name,
            "username": username,
            "password": password,
            "url": url,
            "notes": notes,
            "created": now,
            "modified": now,
        }
        return entry_id

    def update_entry(self, ident: str, *, kind: str | None = None,
                     name: str | None = None, username: str | None = None,
                     password: str | None = None, url: str | None = None,
                     notes: str | None = None) -> str:
        """Update fields of an existing entry. Only non-None fields change."""
        self._assert_unlocked()
        eid = self._resolve(ident)
        entry = self._entries[eid]
        if kind is not None:
            if kind not in KINDS:
                raise AegisError(f"unknown entry kind {kind!r}")
            entry["kind"] = kind
        if name is not None:
            if not name:
                raise AegisError("entry name must not be empty")
            entry["name"] = name
        for field, value in (("username", username), ("password", password),
                             ("url", url), ("notes", notes)):
            if value is not None:
                entry[field] = value
        entry["modified"] = _now()
        return eid

    def _resolve(self, ident: str) -> str:
        """Resolve an exact id, a unique id prefix, or a unique name."""
        self._assert_unlocked()
        if ident in self._entries:
            return ident
        prefixes = [eid for eid in self._entries if eid.startswith(ident)]
        if len(prefixes) == 1:
            return prefixes[0]
        if len(prefixes) > 1:
            raise AegisError(f"ambiguous id prefix {ident!r}")
        by_name = [eid for eid, e in self._entries.items()
                   if e["name"] == ident]
        if len(by_name) == 1:
            return by_name[0]
        if len(by_name) > 1:
            raise AegisError(
                f"multiple entries named {ident!r}; use an id instead")
        raise KeyError(ident)

    def get_entry(self, ident: str) -> dict:
        eid = self._resolve(ident)
        entry = dict(self._entries[eid])
        entry["id"] = eid
        return entry

    def list_entries(self) -> list[dict]:
        self._assert_unlocked()
        rows = []
        for eid, entry in self._entries.items():
            rows.append({
                "id": eid,
                "kind": entry.get("kind", "login"),
                "name": entry["name"],
                "username": entry.get("username", ""),
                "url": entry.get("url", ""),
                "attachments": len(entry.get("attachments", [])),
                "modified": entry.get("modified", 0),
            })
        rows.sort(key=lambda r: (r["name"].lower(), r["id"]))
        return rows

    def all_entries(self) -> list[dict]:
        """Full entry copies (every field) for the web UI. Sorted by name."""
        self._assert_unlocked()
        rows = []
        for eid, entry in self._entries.items():
            row = dict(entry)
            row.setdefault("kind", "login")  # vaults written before kinds
            row["id"] = eid
            rows.append(row)
        rows.sort(key=lambda r: (r["name"].lower(), r["id"]))
        return rows

    def remove_entry(self, ident: str) -> dict:
        self._assert_unlocked()
        eid = self._resolve(ident)
        entry = self._entries.pop(eid)
        # Best-effort blob cleanup. If a later save fails, the on-disk
        # vault still lists the entry and downloads fail kindly with
        # "attachment data is missing" - no data resurrection.
        for meta in entry.get("attachments", []):
            (self.attachments_dir / f"{meta['id']}.bin").unlink(
                missing_ok=True)
        return entry

    def __len__(self) -> int:
        return len(self._entries)

    # -- attachments ----------------------------------------------------------

    @property
    def attachments_dir(self) -> Path:
        """Directory holding encrypted attachment blobs (sibling of the
        vault file: `secrets.ags` -> `secrets.ags.files`). Back it up
        together with the vault file."""
        return self._path.with_name(self._path.name + ".files")

    def _resolve_attachment(self, entry: dict, att_id: str) -> dict:
        for meta in entry.get("attachments", []):
            if meta["id"] == att_id or meta["id"].startswith(att_id):
                return meta
        raise AegisError(
            f"entry {entry['name']!r} has no attachment {att_id!r}")

    def get_attachment(self, ident: str, att_id: str) -> dict:
        """Return one attachment's metadata (validates the id resolves)."""
        self._assert_unlocked()
        entry = self._entries[self._resolve(ident)]
        return dict(self._resolve_attachment(entry, att_id))

    def attach_file(self, ident: str, src_stream, filename: str, *,
                    expected_size: int | None = None,
                    save: bool = True) -> dict:
        """Stream-encrypt `src_stream` into a new attachment on the entry.

        The blob is written first (temp file + fsync + rename); only then
        is metadata registered and the vault saved. A crash in between
        leaves an unreferenced blob, never a dangling reference.
        """
        self._assert_unlocked()
        entry = self._entries[self._resolve(ident)]
        name = _clean_filename(filename)

        att_id = uuid.uuid4().hex
        att_uuid = bytes.fromhex(att_id)
        file_key = bytearray(crypto.random_bytes(crypto.KEY_LEN))
        try:
            wrapped = crypto.wrap_file_key(
                bytes(self._root), self._header.vault_uuid, att_uuid,
                file_key)
            self.attachments_dir.mkdir(exist_ok=True)
            final = self.attachments_dir / f"{att_id}.bin"
            tmp = final.with_name(final.name + ".tmp")
            try:
                with open(tmp, "wb") as dst:
                    size, digest = crypto.seal_stream(
                        file_key, att_uuid, src_stream, dst)
                    dst.flush()
                    os.fsync(dst.fileno())
                if expected_size is not None and size != expected_size:
                    raise AegisError("attachment upload truncated")
                os.replace(tmp, final)
            except BaseException:
                tmp.unlink(missing_ok=True)
                raise
        finally:
            crypto.zeroize(file_key)

        meta = {
            "id": att_id,
            "name": name,
            "size": size,
            "sha256": digest,
            "wrapped_key": base64.b64encode(wrapped).decode("ascii"),
            "created": _now(),
        }
        entry.setdefault("attachments", []).append(meta)
        if save:
            self.save()
        return dict(meta)

    def open_attachment(self, ident: str, att_id: str, dst_stream) -> dict:
        """Stream-decrypt an attachment into `dst_stream`. On a tampered
        blob this raises after writing partial data (see open_stream)."""
        self._assert_unlocked()
        entry = self._entries[self._resolve(ident)]
        meta = self._resolve_attachment(entry, att_id)
        blob = self.attachments_dir / f"{meta['id']}.bin"
        if not blob.exists():
            raise AegisError(
                "attachment data is missing (blob file not found)")
        file_key = bytearray(crypto.unwrap_file_key(
            bytes(self._root), self._header.vault_uuid,
            bytes.fromhex(meta["id"]),
            base64.b64decode(meta["wrapped_key"])))
        try:
            with open(blob, "rb") as src:
                size, digest = crypto.open_stream(
                    file_key, bytes.fromhex(meta["id"]), src, dst_stream)
        finally:
            crypto.zeroize(file_key)
        if size != meta["size"] or digest != meta["sha256"]:
            raise FormatError(
                "attachment failed verification (size or hash mismatch)")
        return dict(meta)

    def remove_attachment(self, ident: str, att_id: str, *,
                          save: bool = True) -> dict:
        """Drop an attachment's metadata (and save), then its blob."""
        self._assert_unlocked()
        entry = self._entries[self._resolve(ident)]
        meta = self._resolve_attachment(entry, att_id)
        entry["attachments"].remove(meta)
        if not entry["attachments"]:
            entry.pop("attachments")
        if save:
            self.save()
        (self.attachments_dir / f"{meta['id']}.bin").unlink(missing_ok=True)
        return dict(meta)


def _clean_filename(name: str) -> str:
    """Sanitize a display/download filename. Blobs are stored under their
    uuid, so this value is only ever metadata and a Content-Disposition
    field - but it still must not carry path separators or control bytes."""
    name = str(name).replace("/", "_").replace("\\", "_").strip()
    if not name:
        raise AegisError("attachment name must not be empty")
    if len(name) > 255:
        raise AegisError("attachment name is too long (max 255)")
    if any(ch in name for ch in "\r\n\x00"):
        raise AegisError("attachment name contains control characters")
    return name
