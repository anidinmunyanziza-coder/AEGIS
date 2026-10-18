"""
Web UI test suite: the HTTP layer over the vault.

Covers the full API lifecycle plus the two attacks a localhost web app
must survive (rationale in aegis/webui.py):
  - DNS rebinding   -> a spoofed Host header is rejected
  - cross-site CSRF -> the per-launch token is required on every API call
"""

from __future__ import annotations

import json
import os
import re
import socket
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path

import pytest

from aegis import webui
from aegis.vault import Vault

FAST = dict(opslimit=1, memlimit=8 * 1024 * 1024)
PW = "correct horse battery staple"


@contextmanager
def running_server(vault_path: Path, keyfile: bytes | None = None):
    httpd, session = webui.make_server(vault_path, keyfile=keyfile, port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd, session, f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        session.lock()
        thread.join(timeout=5)


@pytest.fixture()
def server(tmp_path: Path):
    vpath = tmp_path / "web.ags"
    Vault.create(vpath, PW, **FAST)
    with running_server(vpath) as trio:
        yield trio


def req(base: str, method: str, path: str, *, token: str | None = None,
        body: dict | None = None):
    data = None
    headers = {}
    if token is not None:
        headers["X-Aegis-Token"] = token
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(base + path, data=data, method=method,
                                     headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=15) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def upload_raw(base: str, path: str, token: str, payload: bytes):
    request = urllib.request.Request(
        base + path, data=payload, method="POST",
        headers={"X-Aegis-Token": token,
                 "Content-Type": "application/octet-stream"})
    try:
        with urllib.request.urlopen(request, timeout=15) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def download_raw(base: str, path: str, token: str):
    request = urllib.request.Request(base + path, method="GET",
                                     headers={"X-Aegis-Token": token})
    try:
        with urllib.request.urlopen(request, timeout=15) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


# ---------------------------------------------------------------------------
# Page & state
# ---------------------------------------------------------------------------

def test_index_serves_tokenized_page(server):
    _, session, base = server
    with urllib.request.urlopen(base + "/", timeout=15) as resp:
        html = resp.read().decode("utf-8")
    assert resp.status == 200
    assert "AEGIS" in html
    assert "__AEGIS_TOKEN__" not in html           # placeholder replaced
    assert session.token in html                   # real token embedded


def test_state_when_locked(server):
    _, session, base = server
    status, data = req(base, "GET", "/api/state", token=session.token)
    assert status == 200
    assert data["locked"] is True
    assert data["needs_keyfile"] is False
    assert data["vault"] == "web.ags"


def test_token_required_everywhere(server):
    _, _, base = server
    status, _ = req(base, "GET", "/api/state")
    assert status == 401
    status, _ = req(base, "POST", "/api/unlock", body={"password": PW})
    assert status == 401
    status, _ = req(base, "GET", "/api/items")
    assert status == 401


def test_bad_host_header_rejected(server):
    """DNS-rebinding guard: only loopback Host values are served."""
    httpd, session, _ = server
    port = httpd.server_address[1]
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(
            b"GET /api/state HTTP/1.1\r\n"
            b"Host: evil.example\r\n"
            b"X-Aegis-Token: " + session.token.encode("ascii") + b"\r\n"
            b"Connection: close\r\n\r\n")
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
    assert b"403" in response.split(b"\r\n", 1)[0]


def test_csp_header_and_nonce(server):
    """The page ships under a nonce-bound CSP: only the nonce'd script and
    style blocks may execute; nothing external may load."""
    _, _, base = server
    with urllib.request.urlopen(base + "/", timeout=15) as resp:
        html = resp.read().decode("utf-8")
        csp = resp.headers.get("Content-Security-Policy") or ""
    assert "default-src 'none'" in csp
    assert "connect-src 'self'" in csp
    match = re.search(r'nonce="([A-Za-z0-9_-]+)"', html)
    assert match, "served page carries a nonce"
    nonce = match.group(1)
    assert f"nonce-{nonce}" in csp
    assert html.count(f'nonce="{nonce}"') == 3  # head gate, style, main script
    assert "__AEGIS_NONCE__" not in html
    assert "__AEGIS_TOKEN__" not in html


# ---------------------------------------------------------------------------
# Unlock / lock
# ---------------------------------------------------------------------------

def test_wrong_password_is_401(server):
    _, session, base = server
    status, data = req(base, "POST", "/api/unlock", token=session.token,
                       body={"password": "wrong"})
    assert status == 401
    assert "error" in data


def test_full_item_lifecycle(server):
    _, session, base = server
    token = session.token

    status, _ = req(base, "POST", "/api/unlock", token=token,
                    body={"password": PW})
    assert status == 200

    # add
    status, data = req(base, "POST", "/api/items", token=token, body={
        "kind": "login", "name": "github", "username": "reid",
        "password": "hunter2", "url": "https://github.com"})
    assert status == 200
    item_id = data["id"]

    # list
    status, data = req(base, "GET", "/api/items", token=token)
    assert status == 200
    (item,) = data["items"]
    assert item["kind"] == "login"
    assert item["password"] == "hunter2"

    # update one field, others untouched
    status, _ = req(base, "POST", "/api/items", token=token,
                    body={"id": item_id, "password": "newpw"})
    assert status == 200
    _, data = req(base, "GET", "/api/items", token=token)
    assert data["items"][0]["password"] == "newpw"
    assert data["items"][0]["username"] == "reid"

    # add without a name is rejected
    status, _ = req(base, "POST", "/api/items", token=token,
                    body={"kind": "login"})
    assert status == 400

    # generate
    status, data = req(base, "POST", "/api/generate", token=token,
                       body={"length": 24})
    assert status == 200
    assert len(data["password"]) == 24

    # delete, then delete again -> 404
    status, _ = req(base, "DELETE", f"/api/items/{item_id}", token=token)
    assert status == 200
    status, _ = req(base, "DELETE", f"/api/items/{item_id}", token=token)
    assert status == 404

    # lock -> items endpoint refuses
    status, _ = req(base, "POST", "/api/lock", token=token)
    assert status == 200
    status, _ = req(base, "GET", "/api/items", token=token)
    assert status == 401


def test_note_kind_and_persistence_across_lock_cycle(server):
    _, session, base = server
    token = session.token
    req(base, "POST", "/api/unlock", token=token, body={"password": PW})

    status, _ = req(base, "POST", "/api/items", token=token, body={
        "kind": "note", "name": "wifi codes",
        "notes": "guest: drink-more-ovaltine"})
    assert status == 200

    req(base, "POST", "/api/lock", token=token)
    status, _ = req(base, "POST", "/api/unlock", token=token,
                    body={"password": PW})
    assert status == 200

    status, data = req(base, "GET", "/api/items", token=token)
    assert status == 200
    (item,) = data["items"]
    assert item["kind"] == "note"
    assert item["notes"] == "guest: drink-more-ovaltine"


# ---------------------------------------------------------------------------
# Attachments over HTTP
# ---------------------------------------------------------------------------

def test_attachment_upload_download_delete(server):
    _, session, base = server
    token = session.token
    req(base, "POST", "/api/unlock", token=token, body={"password": PW})
    _, data = req(base, "POST", "/api/items", token=token,
                  body={"kind": "note", "name": "docs"})
    item_id = data["id"]

    payload = os.urandom(50_000)
    status, data = upload_raw(
        base, f"/api/items/{item_id}/attachments?name=scan%20one.bin",
        token, payload)
    assert status == 200
    assert data["size"] == len(payload)
    att_id = data["id"]

    # download returns the exact bytes + a sane Content-Disposition
    status, body, headers = download_raw(
        base, f"/api/items/{item_id}/attachments/{att_id}", token)
    assert status == 200
    assert body == payload
    assert 'filename="scan one.bin"' in headers.get("Content-Disposition", "")

    # the item now lists the attachment
    status, data = req(base, "GET", "/api/items", token=token)
    assert data["items"][0]["attachments"][0]["id"] == att_id

    # delete, then it is gone
    status, _ = req(base, "DELETE",
                    f"/api/items/{item_id}/attachments/{att_id}", token=token)
    assert status == 200
    status, _, _ = download_raw(
        base, f"/api/items/{item_id}/attachments/{att_id}", token)
    assert status == 404

    # unknown item / unknown attachment are 404s, not 500s
    status, _ = upload_raw(base, "/api/items/nope/attachments?name=x",
                           token, b"data")
    assert status == 404
    status, _, _ = download_raw(
        base, f"/api/items/{item_id}/attachments/deadbeef", token)
    assert status == 404


def test_attachment_routes_require_token(server):
    _, _, base = server
    status, _ = upload_raw(base, "/api/items/whatever/attachments?name=x",
                           "wrong-token", b"data")
    assert status == 401


# ---------------------------------------------------------------------------
# Password generator options
# ---------------------------------------------------------------------------

def test_generate_options(server):
    _, session, base = server
    status, data = req(base, "POST", "/api/generate", token=session.token,
                       body={"length": 16, "uppercase": False,
                             "digits": False, "symbols": False})
    assert status == 200
    password = data["password"]
    assert len(password) == 16
    assert all(ch.islower() for ch in password)

    status, data = req(base, "POST", "/api/generate", token=session.token,
                       body={"length": 64})
    assert status == 200
    assert len(data["password"]) == 64


# ---------------------------------------------------------------------------
# Keyfile vaults through the web layer
# ---------------------------------------------------------------------------

def test_keyfile_vault_flow(tmp_path: Path):
    keyfile = os.urandom(32)
    vpath = tmp_path / "kf.ags"
    Vault.create(vpath, PW, keyfile=keyfile, **FAST)

    # session started without the keyfile: state says so, unlock fails
    with running_server(vpath) as (_, session, base):
        status, data = req(base, "GET", "/api/state", token=session.token)
        assert data["needs_keyfile"] is True
        status, _ = req(base, "POST", "/api/unlock", token=session.token,
                        body={"password": PW})
        assert status == 401

    # session started with the keyfile: unlock works
    with running_server(vpath, keyfile=keyfile) as (_, session, base):
        status, _ = req(base, "POST", "/api/unlock", token=session.token,
                        body={"password": PW})
        assert status == 200
        status, _ = req(base, "GET", "/api/items", token=session.token)
        assert status == 200
