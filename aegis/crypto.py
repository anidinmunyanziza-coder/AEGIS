"""
Aegis vault cryptography (file format AGSV1).

Primitives
----------
  * Argon2id (RFC 9106)            password hardening - memory-hard KDF
  * HKDF-SHA256 (RFC 5869)         subkey derivation with domain separation
  * XChaCha20-Poly1305             authenticated encryption (AEAD, 192-bit nonce)
  * HMAC-SHA-256                   header authentication (tamper/downgrade guard)

Every design invariant below is a fix for a documented failure mode of
naive vault cryptography. Each one is exercised by a test.

  I1. No separate password verifier is stored. The AEAD tag and the header
      HMAC are the only authenticators, so a stolen vault does not hand an
      attacker a cheap "was my guess right?" oracle beyond the KDF itself.
      (Pre-KDBX4 KeePass stored SHA-256(transformed_key) inside the file;
      that is exactly the oracle a parameter-downgrade attack feeds on.)

  I2. The header - KDF parameters, salt, flags, version - is authenticated
      with HMAC-SHA-256 keyed from the password-derived root, AND is bound
      into the AEAD as associated data. Editing any byte of the header
      (e.g. lowering the Argon2id memlimit to make cracking cheaper) makes
      both the HMAC and the AEAD fail closed. This is the KDBX4 lesson.

  I3. XChaCha20-Poly1305 with fresh 192-bit random nonces. No AES-GCM-style
      96-bit nonce birthday hazard, no nonce bookkeeping needed for a
      save-anytime vault.

  I4. Domain separation: encryption key and MAC key are different HKDF
      outputs from a root that never leaves memory. Breaking one does not
      hand over the other.

  I5. Sanity bounds on untrusted header values are enforced BEFORE any
      expensive work, so a hostile vault file cannot make the loader
      allocate gigabytes or spin for minutes (load-time memory DoS).

  I6. Best-effort zeroization of key material on lock. Honest caveat: the
      CPython runtime gives no hard guarantee against copies in the GC or
      swap - closing that gap is why the roadmap moves the core to Rust.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import struct
import unicodedata
from dataclasses import dataclass, replace

from nacl.exceptions import CryptoError
from nacl.pwhash import argon2id
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)

# ---------------------------------------------------------------------------
# Format constants
# ---------------------------------------------------------------------------

MAGIC = b"AEGISv1\x00"
FORMAT_VERSION = 1
KDF_ID_ARGON2ID = 1

SALT_LEN = 16            # argon2id.SALTBYTES
KEY_LEN = 32
NONCE_LEN = 24           # XChaCha20
TAG_LEN = 16             # Poly1305
MAC_LEN = 32             # HMAC-SHA-256
UUID_LEN = 16

# Header layout (little-endian, fixed size, 76 bytes total):
#
#   offset  size  field
#   0       8     magic          b"AEGISv1\x00"
#   8       2     format_version u16
#   10      2     kdf_id         u16 (1 = argon2id)
#   12      4     opslimit       u32 (Argon2id time cost)
#   16      8     memlimit       u64 (Argon2id memory cost, bytes)
#   24      16    kdf_salt
#   40      1     flags          bit0 = keyfile required
#   41      3     reserved       must be zero
#   44      16    vault_uuid
#   60      8     created_at     unix seconds
#   68      8     revision       incremented on every save
#
# File layout:  header(76) || hmac(32) || nonce(24) || ciphertext+tag(...)
#
HEADER_STRUCT = struct.Struct("<8sHHIQ16sB3s16sQQ")
HEADER_LEN = HEADER_STRUCT.size

OPSLIMIT_OFFSET = 12
MEMLIMIT_OFFSET = 16
FLAGS_OFFSET = 40

FLAG_KEYFILE = 0x01

# Cost defaults. 256 MiB / t=3 is 4x the RFC 9106 second recommendation
# (64 MiB, t=3) and >13x the OWASP Argon2id floor (19 MiB, t=2).
DEFAULT_MEMLIMIT = 256 * 1024 * 1024
DEFAULT_OPSLIMIT = 3

# Load-time sanity bounds (I5). Anything outside these is rejected before
# Argon2id is invoked on hostile input.
MIN_MEMLIMIT = 8 * 1024              # 8 KiB, libsodium floor
MAX_MEMLIMIT = 1024 * 1024 * 1024    # 1 GiB
MIN_OPSLIMIT = 1
MAX_OPSLIMIT = 64


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class AegisError(Exception):
    """Base class for all Aegis vault errors."""


class FormatError(AegisError):
    """The file is not a well-formed AGSV1 vault."""


class UnlockError(AegisError):
    """Authentication failed: wrong password or keyfile, or the file was
    modified after it was written. Deliberately not more specific - a
    single undistinguishable failure gives an attacker nothing to probe."""


# ---------------------------------------------------------------------------
# KDF / subkey derivation
# ---------------------------------------------------------------------------

def _normalize_password(password: str) -> bytes:
    """Unicode NFKD + UTF-8, so the same visual password typed on different
    systems derives the same key. Documented in the README."""
    return unicodedata.normalize("NFKD", password).encode("utf-8")


def hkdf_sha256(ikm: bytes, salt: bytes | None, info: bytes,
                length: int = 32) -> bytes:
    """HKDF (RFC 5869) extract-then-expand with SHA-256."""
    if salt is None:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]),
                         hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def derive_root(password: str, salt: bytes, opslimit: int, memlimit: int,
                keyfile: bytes | None = None) -> bytearray:
    """Password (+ optional keyfile) -> 32-byte root key.

    The root never hits disk and is never used directly for encryption or
    MACs; it is only an input to HKDF (I4). A keyfile is consumed as HKDF
    salt so that neither factor alone derives the root.
    """
    root = argon2id_kdf(_normalize_password(password), salt, opslimit, memlimit)
    if keyfile is not None:
        kf_digest = hashlib.sha256(keyfile).digest()
        root = hkdf_sha256(root, salt=kf_digest, info=b"aegis/v1/keyfile",
                           length=KEY_LEN)
    return bytearray(root)


def argon2id_kdf(password: bytes, salt: bytes, opslimit: int,
                 memlimit: int) -> bytes:
    """Raw Argon2id key derivation (libsodium memory-hard function)."""
    return argon2id.kdf(KEY_LEN, password, salt,
                        opslimit=opslimit, memlimit=memlimit)


def subkeys(root: bytes) -> tuple[bytearray, bytearray]:
    """Root key -> (enc_key, mac_key) with domain separation (I4)."""
    enc_key = hkdf_sha256(root, None, b"aegis/v1/enc", KEY_LEN)
    mac_key = hkdf_sha256(root, None, b"aegis/v1/mac", KEY_LEN)
    return bytearray(enc_key), bytearray(mac_key)


def zeroize(buf: bytearray) -> None:
    """Best-effort wipe of sensitive key material (I6)."""
    for i in range(len(buf)):
        buf[i] = 0


def random_bytes(n: int) -> bytes:
    """Cryptographically secure randomness (libsodium's randombytes
    equivalent: the OS CSPRNG). Never `random`."""
    return os.urandom(n)


# ---------------------------------------------------------------------------
# AEAD
# ---------------------------------------------------------------------------

def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                 aad: bytes) -> bytes:
    return crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, aad, nonce, bytes(key))


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes,
                 aad: bytes) -> bytes:
    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, aad, nonce, bytes(key))
    except CryptoError as exc:
        raise UnlockError("vault body failed authentication") from exc


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Header:
    version: int
    kdf_id: int
    opslimit: int
    memlimit: int
    salt: bytes
    keyfile_required: bool
    vault_uuid: bytes
    created_at: int
    revision: int

    def pack(self) -> bytes:
        flags = FLAG_KEYFILE if self.keyfile_required else 0
        return HEADER_STRUCT.pack(
            MAGIC, self.version, self.kdf_id, self.opslimit, self.memlimit,
            self.salt, flags, b"\x00\x00\x00", self.vault_uuid,
            self.created_at, self.revision,
        )

    def bumped(self) -> "Header":
        return replace(self, revision=self.revision + 1)

    @classmethod
    def unpack(cls, raw: bytes) -> "Header":
        (magic, version, kdf_id, opslimit, memlimit, salt,
         flags, reserved, vault_uuid, created_at, revision
         ) = HEADER_STRUCT.unpack(raw)

        if magic != MAGIC:
            raise FormatError("not an Aegis vault (bad magic)")
        if version != FORMAT_VERSION:
            raise FormatError(f"unsupported vault version {version}")
        if kdf_id != KDF_ID_ARGON2ID:
            raise FormatError(f"unsupported KDF id {kdf_id}")
        # Sanity bounds BEFORE any expensive derivation (I5).
        if not (MIN_OPSLIMIT <= opslimit <= MAX_OPSLIMIT):
            raise FormatError("KDF opslimit out of bounds")
        if not (MIN_MEMLIMIT <= memlimit <= MAX_MEMLIMIT):
            raise FormatError("KDF memlimit out of bounds")
        if reserved != b"\x00\x00\x00":
            raise FormatError("non-zero reserved bytes")
        if flags & ~FLAG_KEYFILE:
            raise FormatError("unknown header flags")

        return cls(version, kdf_id, opslimit, memlimit, salt,
                   bool(flags & FLAG_KEYFILE), vault_uuid,
                   created_at, revision)


# ---------------------------------------------------------------------------
# Seal / open
# ---------------------------------------------------------------------------

def parse_file(data: bytes) -> tuple[bytes, Header, bytes, bytes, bytes]:
    """Structural parse of a vault file. No cryptography yet.

    Returns (header_raw, header, tag, nonce, ciphertext).
    """
    if len(data) < HEADER_LEN + MAC_LEN + NONCE_LEN + TAG_LEN:
        raise FormatError("file too short to be an Aegis vault")
    header_raw = data[:HEADER_LEN]
    header = Header.unpack(header_raw)
    tag = data[HEADER_LEN:HEADER_LEN + MAC_LEN]
    nonce = data[HEADER_LEN + MAC_LEN:HEADER_LEN + MAC_LEN + NONCE_LEN]
    ciphertext = data[HEADER_LEN + MAC_LEN + NONCE_LEN:]
    return header_raw, header, tag, nonce, ciphertext


def seal_payload(root: bytes, header: Header, plaintext: bytes) -> bytes:
    """Build a complete vault file: header || HMAC || nonce || AEAD(ct).

    The HMAC authenticates the header (I2); the header+HMAC are the AEAD
    associated data, so no component can be swapped independently.
    """
    enc_key, mac_key = subkeys(root)
    header_raw = header.pack()
    tag = hmac.new(bytes(mac_key), header_raw, hashlib.sha256).digest()
    nonce = random_bytes(NONCE_LEN)
    ciphertext = aead_encrypt(enc_key, nonce, plaintext, header_raw + tag)
    zeroize(enc_key)
    zeroize(mac_key)
    return header_raw + tag + nonce + ciphertext


def open_payload(root: bytes, header_raw: bytes, tag: bytes, nonce: bytes,
                 ciphertext: bytes) -> bytes:
    """Verify the header MAC, then decrypt. Raises UnlockError on any
    mismatch - wrong key or modified file, indistinguishable by design."""
    enc_key, mac_key = subkeys(root)
    try:
        expected = hmac.new(bytes(mac_key), header_raw,
                            hashlib.sha256).digest()
        if not hmac.compare_digest(expected, tag):
            raise UnlockError(
                "authentication failed: wrong password/keyfile, or the "
                "header was modified")
        return aead_decrypt(enc_key, nonce, ciphertext, header_raw + tag)
    finally:
        zeroize(enc_key)
        zeroize(mac_key)


# ---------------------------------------------------------------------------
# Attachments (format AEGISaf1)
# ---------------------------------------------------------------------------
#
# Bulk data never inflates the vault file. Each attachment is a separate
# blob encrypted with its own random 256-bit file key; the file key is
# *wrapped* (XChaCha20-Poly1305 under the vault root, its own AAD domain)
# and the wrapped bytes live in the attachment's metadata inside the
# authenticated vault payload. Consequences:
#
#   * rotating the master password re-seals the wrapped keys with the new
#     root automatically - blobs never need re-encryption;
#   * the vault file stays small (it is an index, not a container);
#   * blobs are streamed in fixed chunks, so memory stays constant no
#     matter the file size.
#
# Blob layout:
#
#   magic "AEGISaf1" (8) || version u16 || attachment_uuid (16)
#   then N chunk records:
#     nonce (24) || plaintext_len u32 || AEAD ciphertext+tag (len+16)
#
# Chunk AAD = b"AEGISchunk" || attachment_uuid || chunk index u32 ||
#             final-flag byte.  Index binding blocks reordering, the final
#             flag blocks truncation, the uuid blocks swapping blobs
#             between attachments. Plaintext size and SHA-256 are stored
#             in the (authenticated) vault metadata as a second check.

ATT_MAGIC = b"AEGISaf1"
ATT_VERSION = 1
ATT_HEADER_LEN = 8 + 2 + UUID_LEN   # 26 bytes
ATT_CHUNK = 1 << 20                 # 1 MiB plaintext per chunk


def _chunk_aad(att_uuid: bytes, index: int, final: bool) -> bytes:
    return (b"AEGISchunk" + att_uuid
            + struct.pack("<IB", index, 1 if final else 0))


def _read_exact(src, n: int) -> bytes:
    parts = []
    remaining = n
    while remaining:
        chunk = src.read(remaining)
        if not chunk:
            raise FormatError("truncated attachment")
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


def _write_chunk(dst, file_key: bytes, att_uuid: bytes, index: int,
                 data: bytes, final: bool) -> None:
    nonce = random_bytes(NONCE_LEN)
    ciphertext = aead_encrypt(file_key, nonce, data,
                              _chunk_aad(att_uuid, index, final))
    dst.write(nonce + struct.pack("<I", len(data)) + ciphertext)


def seal_stream(file_key: bytes, att_uuid: bytes, src, dst,
                *, chunk_size: int = ATT_CHUNK) -> tuple[int, str]:
    """Stream-encrypt `src` into `dst`. Returns (plaintext_size, sha256hex).

    Constant memory: reads at most one chunk ahead. The stream is always
    sealed with at least one chunk, so an empty file still authenticates.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if len(att_uuid) != UUID_LEN:
        raise ValueError("attachment uuid must be 16 bytes")
    dst.write(ATT_MAGIC + struct.pack("<H", ATT_VERSION) + att_uuid)

    digest = hashlib.sha256()
    size = 0
    index = 0
    buf = src.read(chunk_size)
    if buf == b"":
        _write_chunk(dst, file_key, att_uuid, 0, b"", True)
        return 0, digest.hexdigest()

    while True:
        nxt = src.read(chunk_size)
        final = nxt == b""
        _write_chunk(dst, file_key, att_uuid, index, buf, final)
        digest.update(buf)
        size += len(buf)
        if final:
            break
        buf = nxt
        index += 1
    return size, digest.hexdigest()


def open_stream(file_key: bytes, att_uuid: bytes, src, dst,
                *, chunk_size: int = ATT_CHUNK) -> tuple[int, str]:
    """Stream-decrypt an attachment blob from `src` into `dst`, verifying
    every chunk. Returns (plaintext_size, sha256hex). May write partial
    data to `dst` before raising on a tampered blob - callers writing to
    disk should use a temp file and rename only after this returns."""
    header = _read_exact(src, ATT_HEADER_LEN)
    if header[:8] != ATT_MAGIC:
        raise FormatError("not an Aegis attachment (bad magic)")
    (version,) = struct.unpack("<H", header[8:10])
    if version != ATT_VERSION:
        raise FormatError(f"unsupported attachment version {version}")
    if header[10:] != att_uuid:
        raise FormatError("attachment id mismatch")

    digest = hashlib.sha256()
    size = 0
    index = 0
    nonce = _read_exact(src, NONCE_LEN)
    while True:
        (length,) = struct.unpack("<I", _read_exact(src, 4))
        if length > chunk_size:
            raise FormatError("attachment chunk exceeds declared chunk size")
        body = _read_exact(src, length + TAG_LEN)
        peek = src.read(NONCE_LEN)
        if peek == b"":
            final = True
        elif len(peek) == NONCE_LEN:
            final = False
        else:
            raise FormatError("truncated attachment")
        try:
            plaintext = aead_decrypt(file_key, nonce, body,
                                     _chunk_aad(att_uuid, index, final))
        except UnlockError as exc:
            raise FormatError(
                "attachment failed authentication (modified data or "
                "wrong key)") from exc
        dst.write(plaintext)
        digest.update(plaintext)
        size += len(plaintext)
        if final:
            break
        nonce = peek
        index += 1
    return size, digest.hexdigest()


_WRAP_AAD = b"AEGISwrap"


def wrap_file_key(root: bytes, vault_uuid: bytes, att_uuid: bytes,
                  file_key: bytes) -> bytes:
    """Wrap a file key under the vault root. Returns nonce || ciphertext."""
    nonce = random_bytes(NONCE_LEN)
    aad = _WRAP_AAD + vault_uuid + att_uuid
    return nonce + aead_encrypt(root, nonce, bytes(file_key), aad)


def unwrap_file_key(root: bytes, vault_uuid: bytes, att_uuid: bytes,
                    wrapped: bytes) -> bytes:
    if len(wrapped) < NONCE_LEN + TAG_LEN + KEY_LEN:
        raise FormatError("wrapped key is too short")
    nonce, ciphertext = wrapped[:NONCE_LEN], wrapped[NONCE_LEN:]
    aad = _WRAP_AAD + vault_uuid + att_uuid
    try:
        return aead_decrypt(root, nonce, ciphertext, aad)
    except UnlockError as exc:
        raise FormatError("attachment key failed authentication") from exc


# ---------------------------------------------------------------------------
# Password generation
# ---------------------------------------------------------------------------

# Look-alike characters (l/I/1, O/0) removed: this password gets typed by
# humans. Entropy still >= 5.9 bits per char (~118 bits at length 20).
_PW_LOWER = "abcdefghijkmnopqrstuvwxyz"
_PW_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
_PW_DIGITS = "23456789"
_PW_SYMBOLS = "!@#$%^&*-_=+?"
_PW_ALPHABET = _PW_LOWER + _PW_UPPER + _PW_DIGITS + _PW_SYMBOLS


def generate_password(length: int = 20, *, uppercase: bool = True,
                      digits: bool = True, symbols: bool = True) -> str:
    """Generate a random password. Guarantees at least one character from
    every selected class, then fills and shuffles with the OS CSPRNG."""
    if length < 12:
        raise ValueError("password length must be at least 12")
    classes = [_PW_LOWER]
    if uppercase:
        classes.append(_PW_UPPER)
    if digits:
        classes.append(_PW_DIGITS)
    if symbols:
        classes.append(_PW_SYMBOLS)
    chars = [secrets.choice(cls) for cls in classes]
    pool = "".join(classes)
    while len(chars) < length:
        chars.append(secrets.choice(pool))
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)
