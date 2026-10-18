"""
Aegis local web UI.

A deliberately thin HTTP layer over the exact same vault code the CLI uses:
no crypto of its own, no remote access. Binds 127.0.0.1 only.

A localhost web server is still attackable from the browser you already
have open, so the loopback server defends against the two classic attacks
on local web apps:

  * DNS rebinding - a malicious site resolves its own domain to 127.0.0.1
    to talk to services on your machine. Defeated by validating the Host
    header against the loopback names (see GitHub's "Localhost dangers:
    CORS and DNS rebinding" writeup).
  * CSRF via plain form posts - a random per-launch token is embedded in
    the served page and required on every API call; arbitrary sites cannot
    read the token and cannot set custom headers without a CORS preflight
    this server never grants.

On top: Content-Security-Policy, no-store caching, no request logging
(leaked paths), and the frontend renders exclusively via textContent so a
malicious note cannot inject script into the vault UI.
"""

from __future__ import annotations

import json
import secrets
import tempfile
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote

from . import crypto
from . import vault as vaultmod
from .crypto import AegisError, UnlockError
from .vault import Vault, KINDS

INDEX_HTML = Path(__file__).with_name("index.html")

MAX_BODY = 1 << 20              # 1 MiB: plenty for a JSON record
MAX_UPLOAD = 256 * 1024 * 1024  # 256 MiB per attachment upload
MAX_FIELD = 20_000              # chars per field
GENERATE_RANGE = (12, 128)


class _LimitedReader:
    """Reads at most `length` bytes from an HTTP request body. Used so
    attachment uploads stream straight into the encryptor instead of
    buffering in memory."""

    def __init__(self, rfile, length: int):
        self._rfile = rfile
        self.remaining = length

    def read(self, size: int = -1) -> bytes:
        if self.remaining <= 0:
            return b""
        if size is None or size < 0:
            size = self.remaining
        data = self._rfile.read(min(size, self.remaining))
        self.remaining -= len(data)
        return data


def _content_disposition(name: str) -> str:
    """RFC 5987 filename with an ASCII fallback; strips anything that
    could break the header (quotes, backslashes, control bytes)."""
    fallback = "".join(ch for ch in name
                       if ch.isprintable() and ch not in '"\\').strip()
    return (f'attachment; filename="{fallback or "download"}"; '
            f"filename*=UTF-8''{quote(name, safe='')}")


class Session:
    """Server-side state: the vault (locked or unlocked) plus the UI token."""

    def __init__(self, vault_path: str | Path, keyfile: bytes | None = None):
        self.vault_path = Path(vault_path)
        self.keyfile = keyfile
        self.token = secrets.token_urlsafe(32)
        self.vault: Vault | None = None
        self.mutex = threading.Lock()

    def unlock(self, password: str) -> Vault:
        with self.mutex:
            vault = Vault.load(self.vault_path, password, keyfile=self.keyfile)
            if self.vault is not None:
                self.vault.lock()
            self.vault = vault
            return vault

    def lock(self) -> None:
        with self.mutex:
            if self.vault is not None:
                self.vault.lock()
                self.vault = None

    def needs_keyfile(self) -> bool:
        """Read the (unauthenticated) header to see if a keyfile is required."""
        try:
            data = self.vault_path.read_bytes()
            header = crypto.parse_file(data)[1]
            return bool(header.keyfile_required)
        except (OSError, AegisError):
            return False


def _make_handler(session: Session):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def version_string(self) -> str:
            return "aegis"

        def log_message(self, fmt, *args) -> None:
            pass  # stay quiet: request lines would echo vault paths

        # -- response helpers ----------------------------------------------

        def _send(self, code: int, body: bytes, ctype: str,
                  extra: list[tuple[str, str]] | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for name, value in (extra or ()):
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, payload: dict) -> None:
            self._send(code, json.dumps(payload).encode("utf-8"),
                       "application/json; charset=utf-8")

        # -- guards ---------------------------------------------------------

        def _host_ok(self) -> bool:
            """DNS-rebinding guard: only accept loopback Host headers."""
            host = (self.headers.get("Host") or "").lower()
            port = self.server.server_address[1]
            return host in (f"127.0.0.1:{port}",
                            f"localhost:{port}",
                            f"[::1]:{port}")

        def _token_ok(self) -> bool:
            supplied = (self.headers.get("X-Aegis-Token") or "").encode(
                "utf-8", "replace")
            return secrets.compare_digest(supplied,
                                          session.token.encode("utf-8"))

        def _read_json(self) -> dict:
            raw_len = self.headers.get("Content-Length")
            try:
                length = int(raw_len or 0)
            except ValueError:
                raise AegisError("malformed request")
            if length <= 0 or length > MAX_BODY:
                raise AegisError("malformed request")
            try:
                data = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise AegisError("malformed request")
            if not isinstance(data, dict):
                raise AegisError("malformed request")
            return data

        def _vault_or_error(self) -> Vault | None:
            if session.vault is None:
                self._json(401, {"error": "vault is locked"})
                return None
            return session.vault

        # -- routing ----------------------------------------------------------

        def do_GET(self) -> None:
            self._route("GET")

        def do_POST(self) -> None:
            self._route("POST")

        def do_DELETE(self) -> None:
            self._route("DELETE")

        def _route(self, method: str) -> None:
            try:
                if not self._host_ok():
                    return self._json(403, {"error": "forbidden host"})
                path, _, raw_query = self.path.partition("?")
                query = parse_qs(raw_query)

                if method == "GET" and path == "/":
                    html = INDEX_HTML.read_text(encoding="utf-8")
                    html = html.replace("__AEGIS_TOKEN__", session.token)
                    nonce = secrets.token_urlsafe(16)
                    html = html.replace("__AEGIS_NONCE__", nonce)
                    csp = (
                        "default-src 'none'; "
                        f"script-src 'nonce-{nonce}'; "
                        f"style-src 'nonce-{nonce}'; "
                        "connect-src 'self'; img-src data:; "
                        "base-uri 'none'; form-action 'none'; "
                        "frame-ancestors 'none'"
                    )
                    return self._send(
                        200, html.encode("utf-8"),
                        "text/html; charset=utf-8",
                        extra=[("Content-Security-Policy", csp)])

                if not path.startswith("/api/"):
                    return self._json(404, {"error": "not found"})
                if not self._token_ok():
                    return self._json(401, {"error": "invalid token"})

                self._api(method, path, query)
            except UnlockError as exc:
                self._json(401, {"error": str(exc)})
            except AegisError as exc:
                self._json(400, {"error": str(exc)})
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception:
                self._json(500, {"error": "internal error"})

        def _api(self, method: str, path: str, query: dict) -> None:
            if method == "GET" and path == "/api/state":
                vault = session.vault
                return self._json(200, {
                    "locked": vault is None,
                    "vault": session.vault_path.name,
                    "needs_keyfile": session.needs_keyfile(),
                    "count": len(vault) if vault else 0,
                    "revision": vault.revision if vault else None,
                })

            if method == "POST" and path == "/api/unlock":
                password = str(self._read_json().get("password") or "")
                vault = session.unlock(password)
                return self._json(200, {
                    "ok": True, "count": len(vault),
                    "revision": vault.revision,
                })

            if method == "POST" and path == "/api/lock":
                session.lock()
                return self._json(200, {"ok": True})

            if method == "POST" and path == "/api/generate":
                data = self._read_json()
                raw = data.get("length", 20)
                try:
                    length = int(raw)
                except (TypeError, ValueError):
                    length = 20
                length = max(GENERATE_RANGE[0], min(GENERATE_RANGE[1], length))
                opts = {}
                for key in ("uppercase", "digits", "symbols"):
                    value = data.get(key)
                    if value is not None:
                        opts[key] = bool(value)
                return self._json(200, {
                    "password": crypto.generate_password(length, **opts)})

            if method == "GET" and path == "/api/items":
                vault = self._vault_or_error()
                if vault is None:
                    return
                return self._json(200, {"items": vault.all_entries(),
                                        "revision": vault.revision})

            if method == "POST" and path == "/api/items":
                vault = self._vault_or_error()
                if vault is None:
                    return
                with session.mutex:
                    eid = self._save_item(vault, self._read_json())
                return self._json(200, {"id": eid})

            if path.startswith("/api/items/"):
                parts = path[len("/api/items/"):].split("/")
                if len(parts) == 2 and parts[1] == "attachments" \
                        and method == "POST":
                    return self._upload_attachment(parts[0], query)
                if len(parts) == 3 and parts[1] == "attachments":
                    if method == "GET":
                        return self._download_attachment(parts[0], parts[2])
                    if method == "DELETE":
                        return self._delete_attachment(parts[0], parts[2])

            if method == "DELETE" and path.startswith("/api/items/"):
                vault = self._vault_or_error()
                if vault is None:
                    return
                ident = path[len("/api/items/"):]
                with session.mutex:
                    try:
                        vault.remove_entry(ident)
                    except KeyError:
                        return self._json(404, {"error": "no such item"})
                    vault.save()
                return self._json(200, {"ok": True})

            return self._json(404, {"error": "not found"})

        def _save_item(self, vault: Vault, data: dict) -> str:
            fields: dict[str, str] = {}
            for key in ("kind", "name", "username", "password", "url", "notes"):
                value = data.get(key)
                if value is None:
                    continue
                value = str(value)
                if len(value) > MAX_FIELD:
                    raise AegisError(f"field {key!r} is too large")
                fields[key] = value
            if fields.get("kind") and fields["kind"] not in KINDS:
                raise AegisError(f"unknown entry kind {fields['kind']!r}")

            item_id = data.get("id")
            if item_id:
                eid = vault.update_entry(str(item_id), **fields)
            else:
                name = fields.pop("name", "")
                if not name:
                    raise AegisError("entry name must not be empty")
                eid = vault.add_entry(name, **fields)
            vault.save()
            return eid

        # -- attachments -----------------------------------------------------

        def _find_attachment(self, item_id: str, att_id: str):
            """Resolve item + attachment to (vault, meta), or send an
            error response and return (None, None)."""
            vault = self._vault_or_error()
            if vault is None:
                return None, None
            try:
                meta = vault.get_attachment(item_id, att_id)
            except KeyError:
                self._json(404, {"error": "no such item"})
                return None, None
            except AegisError:
                self._json(404, {"error": "no such attachment"})
                return None, None
            return vault, meta

        def _upload_attachment(self, item_id: str, query: dict) -> None:
            vault = self._vault_or_error()
            if vault is None:
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if length < 0 or length > MAX_UPLOAD:
                self.close_connection = True  # body not consumed
                return self._json(413, {
                    "error": "upload too large "
                             f"(max {MAX_UPLOAD // (1024 * 1024)} MiB)"})
            name = (query.get("name") or ["file"])[0]
            reader = _LimitedReader(self.rfile, length)
            try:
                with session.mutex:
                    meta = vault.attach_file(item_id, reader, name,
                                             expected_size=length)
            except KeyError:
                return self._json(404, {"error": "no such item"})
            finally:
                if reader.remaining:
                    self.close_connection = True  # keep-alive poisoned
            return self._json(200, {
                "id": meta["id"], "name": meta["name"],
                "size": meta["size"]})

        def _download_attachment(self, item_id: str, att_id: str) -> None:
            vault, meta = self._find_attachment(item_id, att_id)
            if vault is None:
                return
            # Decrypt to a spool first: integrity is verified before a
            # single byte reaches the client, so a tampered blob becomes
            # a clean error instead of a half-corrupt download.
            spool = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)
            try:
                with session.mutex:
                    vault.open_attachment(item_id, meta["id"], spool)
                spool.seek(0)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(meta["size"]))
                self.send_header("Content-Disposition",
                                 _content_disposition(meta["name"]))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                while True:
                    block = spool.read(64 * 1024)
                    if not block:
                        break
                    self.wfile.write(block)
            finally:
                spool.close()

        def _delete_attachment(self, item_id: str, att_id: str) -> None:
            vault, meta = self._find_attachment(item_id, att_id)
            if vault is None:
                return
            with session.mutex:
                vault.remove_attachment(item_id, meta["id"])
            return self._json(200, {"ok": True, "name": meta["name"]})

    return Handler


def make_server(vault_path: str | Path, *, keyfile: bytes | None = None,
                port: int = 0) -> tuple[ThreadingHTTPServer, Session]:
    """Create (but do not start) the loopback server. Port 0 picks a free one."""
    session = Session(vault_path, keyfile=keyfile)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), _make_handler(session))
    httpd.daemon_threads = True
    return httpd, session


def serve(vault_path: str | Path, *, keyfile: bytes | None = None,
          port: int = 8787, open_browser: bool = True) -> int:
    """Run the web UI until Ctrl+C. Locks the vault on the way out."""
    if not Path(vault_path).exists():
        raise AegisError(
            f"vault not found: {vault_path} "
            f"(run `aegis --vault {vault_path} init` first)")
    try:
        httpd, session = make_server(vault_path, keyfile=keyfile, port=port)
    except OSError as exc:
        raise AegisError(f"cannot bind 127.0.0.1:{port} ({exc})")

    url = f"http://127.0.0.1:{httpd.server_address[1]}/"
    print(f"aegis ui: {url}  (Ctrl+C to stop; vault locks on exit)")
    if open_browser:
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        session.lock()
        httpd.server_close()
        print("aegis ui: stopped.")
    return 0
