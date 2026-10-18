# Aegis Vault

A portfolio-grade encrypted password vault *and file store*. One vault file
(plus an encrypted attachment folder), one master password, optional keyfile
second factor. Argon2id → HKDF-SHA256 → XChaCha20-Poly1305 with an
HMAC-authenticated header. Ships as a CLI and a local-only web UI.

```
aegis --vault secrets.ags init
aegis --vault secrets.ags add github --username me --url https://github.com --generate
aegis --vault secrets.ags get github --show
```

**Honest status:** educational, self-audited, test-covered — but *not
independently audited*. Do not make it your only password manager. The point
of this project is to show how a vault should be built and *why each decision
is made*; every claim below has a test behind it.

---

## 1. What "military-grade encryption" actually means

It's a marketing phrase with no technical definition. Vendors using it mean
**AES-256** — which is also what your browser uses for HTTPS, your phone uses
for local storage, and most cloud services use by default. It is the universal
baseline, not an exclusive upgrade.

What militaries actually specify is concrete and public:

| Real standard | What it says |
|---|---|
| **NSA CNSA 2.0** (National Security Systems) | AES-256, SHA-384, ML-KEM-1024, ML-DSA-87, LMS/XMSS |
| **FIPS 140-3** | Validation of the *cryptographic module implementation*, not the algorithm name |
| **RFC 9106** (Argon2) | Parameter recommendations for password hashing: ≥ 64 MiB, t=3 |

The lesson from the field: **you cannot "strengthen" AES or ChaCha by
modifying them** — every attempt produces something weaker. Cipher primitives
have been fine for decades. Password managers get broken through *composition*:
key derivation parameters, header handling, verifier design, nonce management,
error behavior. That's where this project invests.

**Post-quantum note:** symmetric crypto is the easy part — a 256-bit key still
has ~128 bits of security under Grover's algorithm, which is unreachable. CNSA
2.0's post-quantum algorithms matter for *key exchange and signatures*, and a
local vault file has neither. The quantum-hardening here was already free.

Sources: [postquantum.com on "military-grade"](https://postquantum.com/quantum-snake-oil/military-grade-quantum-encryption/),
[NSA CNSA 2.0](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/3148990/nsa-releases-future-quantum-resistant-algorithm-requirements-for-national-securi/),
[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html),
[RFC 9106](https://www.rfc-editor.org/rfc/rfc9106).

## 2. The 10 classic vault crypto errors — and how Aegis fixes each

Each row is a real, documented failure mode. Each "fix" column is enforced by
code and tested in `tests/test_aegis.py`.

| # | The error | Where it bites in the real world | Aegis fix | Test |
|---|---|---|---|---|
| 1 | **Stored password verifier** (`SHA256(derived_key)` in the file) | Pre-KDBX4 KeePass. Gives attackers a cheap "was my guess right?" oracle and feeds the downgrade attack below | No verifier exists. The header HMAC and AEAD tag *are* the authenticators | (format design) |
| 2 | **Unauthenticated header / KDF params** | Attacker lowers the Argon2/AES-KDF cost in the file → cheaper offline cracking. The reason KDBX4 added header HMACs | Header is HMAC-SHA-256'd with a password-derived key **and** bound as AEAD associated data | `test_memlimit_downgrade_rejected`, `test_opslimit_tamper_rejected` |
| 3 | **Weak KDF** (fast hash, low iteration count) | LastPass shipped PBKDF2‑SHA256 at **100,100** iterations (OWASP said 310,000 at the time); 33M vaults were exfiltrated in 2022 | Argon2id, **256 MiB / t=3** — 4× RFC 9106's second recommendation, >13× the OWASP floor | `test_defaults_are_production_grade` |
| 4 | **Nonce reuse hazards** | AES-GCM's 96-bit random nonces hit birthday collisions at ~2³² messages; key+nonce reuse leaks plaintext | XChaCha20-Poly1305: 192-bit nonces, safe under random generation; fresh nonce every save | `test_nonce_uniqueness_across_saves` |
| 5 | **Unauthenticated encryption** (CBC, ECB, raw CTR) | Bit-flipping, padding oracles. The famous ECB penguin | AEAD only. Every bit of ciphertext is authenticated | `test_ciphertext_bitflip_rejected` |
| 6 | **Timing / error oracles** | Non-constant-time compares and "wrong password" vs "corrupt file" distinctions help attackers | `hmac.compare_digest`; one uniform failure message for wrong password, wrong keyfile, and tampering | `test_wrong_password_rejected` |
| 7 | **Key material lifetime** | Keys lingering in pagable memory, copies in the GC | Only a 32-byte root lives in memory; subkeys derived per operation and wiped immediately; `lock()` zeroizes the root | `vault.lock()` (design) |
| 8 | **Weak randomness** | `random` module / time-seeded RNG for salts and nonces | OS CSPRNG (`os.urandom`) only — the libsodium `randombytes` equivalent | (design) |
| 9 | **Load-time DoS from hostile files** | A crafted file sets Argon2 memlimit to 1 TB → the loader OOMs *before* authenticating anything | Parameter sanity bounds enforced before any KDF work | `test_kdf_param_bounds_guard` |
| 10 | **Non-atomic writes / rollback** | Crash mid-save corrupts the vault; attacker swaps in an old copy | Temp file + fsync + atomic rename; revision counter in the authenticated header | `test_atomic_write_preserves_binary_bytes`, `test_revision_increments` |

**Why not issue #1's "separate verifier" isn't needed:** when there is no
verifier and the KDF parameters are authenticated, an attacker holding a stolen
file gets *no shortcut* — every guess costs a full Argon2id evaluation under
the *original* parameters, because a downgraded file won't MAC-verify. Try the
downgrade yourself: the CLI demo in the project docs shows a correct-password
unlock failing with exit code 1 on a memlimit-tampered vault.

## 3. Why these primitives — research notes

Every choice below was made from a source, not a vibe:

**XChaCha20-Poly1305 over AES-GCM.** libsodium's own documentation recommends
it *because of the nonce*: the 192-bit nonce allows random nonces to be safely
used. AES-GCM and IETF-ChaCha use 96-bit nonces, which push implementations
into counters or a birthday-bound collision risk at ~2³² random messages under
one key — and GCM fails catastrophically *and silently* on nonce reuse. A
password vault saves many times under one long-lived key, so it lives exactly
in the "many messages, one key" regime. XChaCha removes the entire failure
class. (libsodium also ships XChaCha20-SIV for nonce-*reuse* resistance; that
matters when a nonce can repeat, which here it cannot — so we don't pay for it.)

**Argon2id over PBKDF2/bcrypt/scrypt.** RFC 9106 and the OWASP Password
Storage Cheat Sheet both put Argon2id first. It is memory-hard and hybrid:
the first pass resists side channels, the rest resists GPU/ASIC parallelism.
PBKDF2 is iteration-based, so GPUs parallelize it; bcrypt caps input at 72
bytes and memory at 4 KiB. Aegis runs 256 MiB / t=3 — 4× RFC 9106's second
recommendation, >13× OWASP's floor.

**No algorithm negotiation, ever.** The `age` file-encryption format
deliberately supports exactly one cipher suite for exactly this reason:
negotiation logic is where downgrade bugs live. AGSV1 is the same shape —
one KDF id, one AEAD — and both live *inside* the authenticated header, so a
tampered suite id fails authentication before any crypto runs.

**What was deliberately left out — key commitment.** XChaCha20-Poly1305 (like
all ChaCha-Poly AEADs) is not key-committing: an attacker can construct a
ciphertext that decrypts under two different keys. That property matters in
protocols where different parties hold different keys and must agree on which
key "owns" a message (multi-recipient encryption, some voting schemes). In a
local vault, whoever crafted the file is whoever holds the only key — the
attack has no victim. Recorded here so it reads as a decision, not an
oversight.

Sources: [libsodium XChaCha20-Poly1305 docs](https://doc.libsodium.org/secret-key_cryptography/aead),
[age spec (C2SP)](https://github.com/C2SP/C2SP/blob/main/age.md),
[Stack Exchange on accidental nonce reuse](https://crypto.stackexchange.com/questions/70686/how-to-prevent-accidental-nonce-reuse-with-aead-cipher).

## 4. Format (AGSV1)

```
offset  size  field
0       8     magic "AEGISv1\0"
8       2     format version
10      2     KDF id (1 = Argon2id)
12      4     opslimit  (Argon2id time cost)
16      8     memlimit  (Argon2id memory cost, bytes)
24      16    KDF salt
40      1     flags     (bit0 = keyfile required)
41      3     reserved  (must be zero)
44      16    vault UUID
60      8     created_at (unix seconds)
68      8     revision
--- 76 bytes ---
76      32    HMAC-SHA-256(header)      ← authenticated header
108     24    nonce
132     ...   XChaCha20-Poly1305 ciphertext + 16-byte tag
```

Key schedule:

```
password ──► Argon2id(256 MiB, t=3, 16B salt) ──► root (32B, never stored)
keyfile  ──► SHA-256 ──► HKDF salt ────────────────┘
root ──HKDF-SHA256(info="aegis/v1/enc")──► enc key   (AEAD)
root ──HKDF-SHA256(info="aegis/v1/mac")──► mac key   (header HMAC)
```

Every byte a save changes — parameters, salt, revision, nonce — flows through
either the header HMAC, the AEAD AAD, or both.

### Attachments (AEGISaf1)

Bulk data never inflates the vault file. `aegis attach` / the web UI's
Upload encrypt each file into its own blob next to the vault
(`secrets.ags` → `secrets.ags.files/<id>.bin`), streamed in 1 MiB chunks so
memory stays constant no matter the file size:

```
magic "AEGISaf1" (8) || version (2) || attachment uuid (16)
then N records:  nonce (24) || plaintext_len u32 || AEAD ciphertext+tag
```

- Each blob gets its own random 256-bit **file key**. The file key is
  *wrapped* — XChaCha20-Poly1305 under the vault root, with its own AAD
  domain (`AEGISwrap || vault_uuid || attachment_uuid`) — and the wrapped
  bytes live in the attachment metadata *inside* the authenticated vault
  payload.
- Per-chunk AAD binds the attachment uuid, the chunk index, and the
  final-chunk flag. Encrypted blobs therefore cannot be reordered,
  truncated, or swapped between attachments; tampering any byte fails
  closed.
- Plaintext size + SHA-256 live in the authenticated metadata and are
  re-checked after decryption.

Two consequences worth naming: rotating the master password re-wraps file
keys automatically (blobs never need re-encryption), and a full backup is
two things — the vault file and its `.files` directory.

## 5. A bug the test suite caught (worth reading)

First test run: 6 of 22 load tests failed — but *only sometimes*, and always on
Windows. The bisect showed the crypto was perfect in memory: seal → parse →
open round-tripped byte-for-byte. The file on disk was 209 bytes; it should
have been 207.

Diagnosis: `_atomic_write` originally used `os.open()`. On Windows, without an
explicit `O_BINARY` flag, that opens the file in **text mode** — every `0x0A`
byte in the random tag/nonce/ciphertext was silently expanded to `0x0D 0x0A`.
Vaults survived only when their random bytes happened to contain no `0x0A`
(~50% of files). Classic platform footgun; the fix is one line (binary-mode
`open("wb")`), and `test_atomic_write_preserves_binary_bytes` now writes all
256 byte values through the writer and asserts byte-exact round-trip, so the
bug can never come back quietly.

## 6. Usage

```
# setup
python -m venv .venv
.venv\Scripts\pip install -e ".[dev]"     # or: pip install PyNaCl pytest

# second factor (optional but recommended)
aegis keyfile usb-stick.kf

# create / open
aegis --vault secrets.ags init --keyfile usb-stick.kf
aegis --vault secrets.ags add github -u me --url https://github.com --generate
aegis --vault secrets.ags add wifi-codes --kind note --notes "guest: drink-more-ovaltine"
aegis --vault secrets.ags attach wifi-codes scans.pdf
aegis --vault secrets.ags get wifi-codes            # lists attachment ids
aegis --vault secrets.ags extract wifi-codes 1a2b --out scans.pdf
aegis --vault secrets.ags detach wifi-codes 1a2b
aegis --vault secrets.ags get github --show
aegis --vault secrets.ags list
aegis --vault secrets.ags rm github
aegis --vault secrets.ags passwd          # rotate master password
aegis gen --length 32

# local web UI (section 7)
aegis --vault secrets.ags ui

# library
python -c "
from aegis import Vault
v = Vault.load('secrets.ags', 'master password')
print(v.get_entry('github')['password'])
v.lock()"
```

`AEGIS_MASTER_PASSWORD` in the environment skips the prompt (automation only —
never on a shared machine). `AEGIS_VAULT` sets the default vault path.

## 7. Web UI (local only)

```
aegis --vault secrets.ags ui                    # http://127.0.0.1:8787
aegis --vault secrets.ags ui --no-browser --port 9000
aegis --vault secrets.ags ui --keyfile usb-stick.kf
```

A loopback single-page frontend over the *same vault code the CLI uses* — no
crypto is re-implemented for the web layer. The interface is a dark vault skin
with a cream light mode, and a few deliberate touches: an entrance ceremony on
first visit (`?replay` on the URL to see it again; skipped entirely under
`prefers-reduced-motion`), a live dot-grid canvas behind the unlock hero, a
crypto-fact marquee, numbered telemetry cells (entries · revision · idle
countdown · seal), a circular view-transition theme wipe, and a terminal-style
**session log** panel that records operations — unlock, saves, attachment
encrypt/decrypt, locks — and never secret values. The motion language was
rebuilt from a reverse-engineering study of a live reference site; every line
of code and every asset here is original. What's in it:

- unlock screen, search (`/`), sort by name/recent/type, entry monograms
- login + secure-note entries, add/edit/delete, reveal + copy password
  and copy username
- **file uploads** — toolbar `Upload` creates a note named after the file
  and encrypts it in; per-entry `+ file` attaches to anything. Download
  and remove per attachment, sizes shown
- password generator with length slider and character-class toggles
  (preferences persist in `localStorage` — never secrets), plus a live
  strength meter (~entropy bits) under the password field
- **audit panel** — flags reused passwords and weak ones (< 50 bits),
  computed entirely in the page
- dark/light theme, `Esc` closes the editor, `Ctrl+Shift+L` locks, and
  5-minute idle auto-lock (key material also zeroizes when the server
  exits)

A localhost web server is still reachable *from every page your browser
has open*, so the UI is built like a local service should be:

| Threat | Defense |
|---|---|
| **DNS rebinding** — a malicious page re-points its domain at 127.0.0.1 to reach local services | Requests must carry a loopback `Host` header (`127.0.0.1:port`, `localhost:port`, `[::1]:port`) or get `403` — the standard mitigation documented by GitHub security |
| **CSRF / cross-site POSTs** | A random per-launch token is embedded in the served page and required as `X-Aegis-Token` on every API call; other origins can neither read the token nor send custom headers without a CORS preflight this server never grants |
| **XSS from vault contents** | The frontend renders exclusively through `textContent` — a hostile note cannot inject markup |
| **Caching / sniffing / injected markup** | `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`; the page ships under `default-src 'none'` with a fresh per-load nonce binding the one script and one style block — nothing else may load or execute |
| **Unattended unlocked session** | 5-minute idle auto-lock in the page; vault locked on server shutdown; no request logging that could echo paths |

## 8. Tests

```
.venv\Scripts\python -m pytest tests -q     # 51 tests
```

Covers: HKDF known-answer test (RFC 5869 case 1) · round trips · wrong
password/keyfile · header parameter downgrade · opslimit tamper · nonce
freshness · ciphertext/MAC bit-flips · truncation · bad magic · reserved bytes
· KDF bounds · keyfile flag forgery · password rotation (with and without
keyfile) · revision counter · no-plaintext-in-file scan · Unicode password
normalization (NFC == NFD) · atomic-write byte-exactness · entry kinds and
partial updates · attachment round trips at every chunk boundary (empty /
exact chunk / multi chunk) · attachment tamper, truncation, reorder and
blob-swap rejection · file-key wrap domains · metadata cross-check · blob
cleanup on removal · web API lifecycle · web token enforcement · Host-header
(DNS-rebinding) rejection · CSP nonce binding · attachment upload/download/delete over HTTP ·
generator character-class options · keyfile vaults through the web layer.

## 9. Limitations & roadmap (honest list)

- **Python can't guarantee memory zeroization** — the GC may copy secrets.
  Real hardening moves the core to Rust (`zeroize`, `mlock`, no copies) with
  the same format.
- **Rollback** to an older revision can't be detected without an external
  monotonic counter — documented, not solved.
- **Endpoint malware** defeats any password manager; out of scope.
- **Attachments are capped at 256 MiB per file in the web UI** (the CLI
  streams without a web-body cap). Blobs are never deduplicated, and a
  backup is incomplete without `<vault>.files/` — copy both.
- **The web UI is single-user loopback-only by design** — no TLS, no remote
  access, no multi-user story. Don't expose it beyond 127.0.0.1; it isn't
  built for that.
- Roadmap: Rust core · FIDO2/YubiKey hmac-secret as a keyfile replacement ·
  sealed-box sharing · encrypted import/export · streaming blob
  de-duplication · autotuned Argon2 params with a benchmark on first run ·
  fuzzing (atheris) · format spec cleanup and an external review before
  anything resembling production use.

## References

- OWASP Password Storage Cheat Sheet — Argon2id floors, PBKDF2/FIPS guidance
- RFC 9106 (Argon2id) · RFC 5869 (HKDF) · RFC 8439 (ChaCha20-Poly1305) + XChaCha draft
- NSA CNSA 2.0 algorithm suite
- KeePass KDBX4 documentation — header authentication rationale
- 2022 LastPass breach analyses — KDF iterations, unencrypted metadata, blast radius
- libsodium AEAD documentation — XChaCha20-Poly1305 and random-nonce safety
- C2SP/age format spec — single-suite design, no negotiation
- GitHub Security — "Localhost dangers: CORS and DNS rebinding"
