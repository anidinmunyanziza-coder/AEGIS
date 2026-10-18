"""
Aegis command-line interface.

    aegis --vault secrets.ags init
    aegis --vault secrets.ags add github --username reid --url https://github.com --generate
    aegis --vault secrets.ags get github --show
    aegis --vault secrets.ags list
    aegis --vault secrets.ags add wifi-codes --kind note --notes "guest: xyz"
    aegis --vault secrets.ags attach scans scans.pdf
    aegis --vault secrets.ags extract scans 1a2b --out scans.pdf
    aegis --vault secrets.ags rm github
    aegis --vault secrets.ags passwd
    aegis --vault secrets.ags ui
    aegis keyfile new.kf
    aegis gen --length 24

Master password is read from a getpass prompt, or from the environment
variable AEGIS_MASTER_PASSWORD for automation and tests (see README - never
use the env var on a shared machine).
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from . import crypto
from . import vault as vaultmod
from .crypto import AegisError, DEFAULT_MEMLIMIT, DEFAULT_OPSLIMIT
from .vault import Vault


def _human(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


# ---------------------------------------------------------------------------
# Password input
# ---------------------------------------------------------------------------

def _master_password(*, confirm: bool = False) -> str:
    env = os.environ.get("AEGIS_MASTER_PASSWORD")
    if env is not None:
        return env
    pw = getpass.getpass("Master password: ")
    if confirm:
        again = getpass.getpass("Confirm master password: ")
        if pw != again:
            raise SystemExit("aegis: passwords do not match")
    return pw


def _new_master_password() -> str:
    env = os.environ.get("AEGIS_NEW_MASTER_PASSWORD")
    if env is not None:
        return env
    pw = getpass.getpass("New master password: ")
    if getpass.getpass("Confirm new master password: ") != pw:
        raise SystemExit("aegis: passwords do not match")
    return pw


def _keyfile_bytes(args) -> bytes | None:
    if getattr(args, "keyfile", None):
        return vaultmod.read_keyfile(args.keyfile)
    return None


def _open(args) -> Vault:
    return Vault.load(args.vault, _master_password(), keyfile=_keyfile_bytes(args))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init(args) -> int:
    memlimit = args.mem_mib * 1024 * 1024
    keyfile = _keyfile_bytes(args)
    Vault.create(args.vault, _master_password(confirm=True), keyfile=keyfile,
                 opslimit=args.ops, memlimit=memlimit)
    print(f"vault created: {args.vault}")
    print(f"  key derivation: Argon2id, memlimit={args.mem_mib} MiB, opslimit={args.ops}")
    if args.keyfile:
        print(f"  second factor:  keyfile {args.keyfile!r} is required to unlock")
    return 0


def cmd_add(args) -> int:
    vault = _open(args)
    generated = None
    if args.kind == "note":
        entry_pw = ""
    elif args.generate:
        entry_pw = crypto.generate_password()
        generated = entry_pw
    elif args.password_stdin:
        entry_pw = sys.stdin.readline().rstrip("\n")
    else:
        entry_pw = getpass.getpass("Entry password: ")

    eid = vault.add_entry(args.name, kind=args.kind,
                          username=args.username or "",
                          password=entry_pw, url=args.url or "",
                          notes=args.notes or "")
    vault.save()
    vault.lock()
    print(f"added {args.name!r} (id {eid[:8]})")
    if generated:
        print(f"generated password: {generated}")
    return 0


def _print_attachments(entry: dict) -> None:
    atts = entry.get("attachments", [])
    if not atts:
        return
    print(f"Files:     {len(atts)}")
    for a in atts:
        print(f"  {a['id'][:8]}  {a['name']} ({_human(a['size'])})")


def cmd_get(args) -> int:
    vault = _open(args)
    entry = vault.get_entry(args.name)
    vault.lock()
    kind = entry.get("kind", "login")
    print(f"Name:      {entry['name']}")
    print(f"ID:        {entry['id']}")
    if kind == "note":
        print("Kind:      note")
        if entry.get("notes"):
            print("Notes:")
            print(entry["notes"])
        _print_attachments(entry)
        return 0
    pw = entry["password"]
    shown = pw if args.show else f"[hidden] ({len(pw)} chars, use --show)"
    print(f"Username:  {entry['username']}")
    print(f"URL:       {entry['url']}")
    print(f"Password:  {shown}")
    if entry["notes"]:
        print(f"Notes:     {entry['notes']}")
    _print_attachments(entry)
    return 0


def cmd_list(args) -> int:
    vault = _open(args)
    rows = vault.list_entries()
    vault.lock()
    if not rows:
        print("vault is empty")
        return 0
    print(f"{'ID':<10} {'NAME':<24} {'USERNAME':<24} URL")
    for r in rows:
        suffix = f"  [+{r['attachments']}]" if r.get("attachments") else ""
        print(f"{r['id'][:8]:<10} {r['name']:<24} "
              f"{r['username']:<24} {r['url']}{suffix}")
    return 0


def cmd_attach(args) -> int:
    vault = _open(args)
    path = Path(args.path)
    with open(path, "rb") as src:
        meta = vault.attach_file(args.name, src, path.name)
    vault.lock()
    print(f"attached {meta['name']!r} ({_human(meta['size'])}) "
          f"as {meta['id'][:8]}")
    return 0


def cmd_detach(args) -> int:
    vault = _open(args)
    meta = vault.get_attachment(args.name, args.att_id)
    if not args.yes:
        answer = input(f"remove attachment {meta['name']!r} "
                       f"({_human(meta['size'])})? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("aborted")
            return 1
    vault.remove_attachment(args.name, args.att_id)
    vault.lock()
    print(f"removed attachment {meta['name']!r}")
    return 0


def cmd_extract(args) -> int:
    vault = _open(args)
    try:
        meta = vault.get_attachment(args.name, args.att_id)
        out = Path(args.out) if args.out else Path(meta["name"])
        if out.exists() and not args.force:
            raise AegisError(f"refusing to overwrite {out} (use --force)")
        tmp = out.with_name(out.name + ".tmp")
        try:
            with open(tmp, "wb") as dst:
                vault.open_attachment(args.name, args.att_id, dst)
            os.replace(tmp, out)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
    finally:
        vault.lock()
    print(f"extracted {meta['name']!r} -> {out} ({_human(meta['size'])})")
    return 0


def cmd_rm(args) -> int:
    vault = _open(args)
    entry = vault.get_entry(args.name)
    if not args.yes:
        answer = input(f"remove {entry['name']!r} (id {entry['id'][:8]})? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("aborted")
            return 1
    vault.remove_entry(entry["id"])
    vault.save()
    vault.lock()
    print(f"removed {entry['name']!r}")
    return 0


def cmd_passwd(args) -> int:
    vault = _open(args)
    vault.change_master_password(_new_master_password())
    revision = vault.revision
    vault.lock()
    print(f"master password rotated; vault re-sealed (revision {revision})")
    return 0


def cmd_keyfile(args) -> int:
    path = vaultmod.generate_keyfile(args.path)
    print(f"keyfile written: {path} (32 random bytes)")
    print("store it on separate media from the vault and its backups;")
    print("losing it makes the vault permanently unopenable")
    return 0


def cmd_gen(args) -> int:
    print(crypto.generate_password(args.length))
    return 0


def cmd_ui(args) -> int:
    from .webui import serve
    keyfile = _keyfile_bytes(args)
    if keyfile is not None:
        print(f"keyfile loaded: {args.keyfile} ({len(keyfile)} bytes)")
    return serve(args.vault, keyfile=keyfile, port=args.port,
                 open_browser=not args.no_browser)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis encrypted vault: Argon2id + XChaCha20-Poly1305 "
                    "with an authenticated header.",
    )
    parser.add_argument(
        "--vault",
        default=os.environ.get("AEGIS_VAULT", "vault.ags"),
        help="vault file path (default: $AEGIS_VAULT or ./vault.ags)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create a new vault")
    p.add_argument("--keyfile", metavar="PATH",
                   help="existing keyfile to require as a second factor")
    p.add_argument("--mem-mib", type=int, default=DEFAULT_MEMLIMIT // (1024 * 1024),
                   help="Argon2id memory cost in MiB (default: %(default)s)")
    p.add_argument("--ops", type=int, default=DEFAULT_OPSLIMIT,
                   help="Argon2id time cost (default: %(default)s)")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("add", help="add or overwrite an entry by name")
    p.add_argument("name")
    p.add_argument("--kind", choices=("login", "note"), default="login",
                   help="entry type (default: %(default)s)")
    p.add_argument("-u", "--username", default="")
    p.add_argument("--url", default="")
    p.add_argument("--notes", default="")
    source = p.add_mutually_exclusive_group()
    source.add_argument("--generate", action="store_true",
                        help="generate a strong password for the entry")
    source.add_argument("--password-stdin", action="store_true",
                        help="read the entry password from stdin (one line)")
    p.add_argument("--keyfile", metavar="PATH",
                   help="keyfile if the vault requires one")
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("get", help="show an entry (id prefix or exact name)")
    p.add_argument("name")
    p.add_argument("--show", action="store_true",
                   help="reveal the password in plain text")
    p.add_argument("--keyfile", metavar="PATH",
                   help="keyfile if the vault requires one")
    p.set_defaults(func=cmd_get)

    p = sub.add_parser("list", help="list entries")
    p.add_argument("--keyfile", metavar="PATH",
                   help="keyfile if the vault requires one")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("rm", help="remove an entry")
    p.add_argument("name")
    p.add_argument("--yes", action="store_true", help="skip confirmation")
    p.add_argument("--keyfile", metavar="PATH",
                   help="keyfile if the vault requires one")
    p.set_defaults(func=cmd_rm)

    p = sub.add_parser("attach", help="encrypt a file into an entry")
    p.add_argument("name")
    p.add_argument("path", help="file to attach")
    p.add_argument("--keyfile", metavar="PATH",
                   help="keyfile if the vault requires one")
    p.set_defaults(func=cmd_attach)

    p = sub.add_parser("detach", help="remove an attachment")
    p.add_argument("name")
    p.add_argument("att_id", help="attachment id (or unique prefix)")
    p.add_argument("--yes", action="store_true", help="skip confirmation")
    p.add_argument("--keyfile", metavar="PATH",
                   help="keyfile if the vault requires one")
    p.set_defaults(func=cmd_detach)

    p = sub.add_parser("extract", help="decrypt an attachment to a file")
    p.add_argument("name")
    p.add_argument("att_id", help="attachment id (or unique prefix)")
    p.add_argument("--out", metavar="PATH",
                   help="destination path (default: the attachment's name)")
    p.add_argument("--force", action="store_true",
                   help="overwrite an existing file")
    p.add_argument("--keyfile", metavar="PATH",
                   help="keyfile if the vault requires one")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("passwd", help="rotate the master password")
    p.add_argument("--keyfile", metavar="PATH",
                   help="keyfile if the vault requires one")
    p.set_defaults(func=cmd_passwd)

    p = sub.add_parser("keyfile", help="generate a new keyfile (second factor)")
    p.add_argument("path")
    p.set_defaults(func=cmd_keyfile)

    p = sub.add_parser("gen", help="generate a standalone password")
    p.add_argument("--length", type=int, default=20)
    p.set_defaults(func=cmd_gen)

    p = sub.add_parser("ui", help="launch the local web UI (127.0.0.1 only)")
    p.add_argument("--port", type=int, default=8787,
                   help="port to listen on (default: %(default)s)")
    p.add_argument("--no-browser", action="store_true",
                   help="do not open a browser window")
    p.add_argument("--keyfile", metavar="PATH",
                   help="keyfile if the vault requires one")
    p.set_defaults(func=cmd_ui)

    return parser


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        return args.func(args) or 0
    except AegisError as exc:
        print(f"aegis: {exc}", file=sys.stderr)
        return 1
    except KeyError as exc:
        print(f"aegis: no entry matches {exc.args[0]!r}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"aegis: file not found: {exc.filename}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
