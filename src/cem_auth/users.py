"""Staff users from the command line; the Staff users page (/users, users_web.py) does the same in the browser, and
this stays the way back in when no Admin can sign in. Run inside the container:

    python -m cem_auth.users keygen /run/secrets/jwt_ed25519.pem
    python -m cem_auth.users add <username> "<Name>" "Admin"                 # prints a one-time enrolment link
    python -m cem_auth.users add <username> "<Name>" "Yard operator:L1" "Lab (QC):All:Coal"
    python -m cem_auth.users roles <username> "Port foreman" "Viewer"
    python -m cem_auth.users reset <username>                     # a new enrolment link; sessions and passkeys end
    python -m cem_auth.users disable|enable <username>
    python -m cem_auth.users list

A role is "Role[:line[:material[:port yes|no]]]"; line All|L1|L2|None, material All|Coal|Non-coal|None. The scope
is stored now and enforced in phase 2. Every change goes in the audit log as "cli". The link is printed only
here: run this in your own terminal (never through a chat or a shared log) and hand the link over yourself."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from cem_auth import staff, tokens
from cem_auth.config import HOST, settings

BY = "cli"


def _role(arg: str) -> dict:
    parts = arg.split(":")
    r = {"role": parts[0], "line": parts[1] if len(parts) > 1 else "All",
         "material": parts[2] if len(parts) > 2 else "All",
         "port": (parts[3].lower() in ("yes", "true", "1")) if len(parts) > 3 else True}  # fmt: skip
    return r


def _link(tok: str) -> str:
    return f"{settings().public_url.rstrip('/')}/enrol/{tok}"


def _user(c, username: str) -> dict:
    u = staff.by_username(c, username)
    if not u:
        sys.exit(f"no user {username}")
    return u


def main(argv: list[str]) -> None:
    if not argv or argv[0] in ("-h", "--help"):
        sys.exit(__doc__)
    cmd, args = argv[0], argv[1:]
    if cmd == "keygen":
        path = Path(args[0] if args else settings().jwt_key_file)
        if path.exists():
            sys.exit(f"{path} exists: not overwritten")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(tokens.new_key_pem())
        print(f"wrote {path} (0600)")
        return
    staff.migrate()
    with staff.engine().begin() as c:
        if cmd == "add":
            if len(args) < 3:
                sys.exit("add <username> <name> <role> [<role> ...]; roles: " + ", ".join(HOST.roles))
            uid, tok = staff.create(c, args[0], args[1], [_role(a) for a in args[2:]], BY)
            print(f"user {args[0]} (id {uid}) created; scope not enforced yet (phase 2)")
            print(f"enrolment link, valid {settings().enrol_link_hours} h, once: {_link(tok)}")
        elif cmd == "roles":
            staff.set_roles(c, _user(c, args[0])["id"], [_role(a) for a in args[1:]], BY)
            print(f"roles of {args[0]} set; open sessions ended; scope not enforced yet (phase 2)")
        elif cmd == "reset":
            tok = staff.reset(c, _user(c, args[0])["id"], BY)
            print(f"{args[0]} reset; sessions ended. New enrolment link: {_link(tok)}")
        elif cmd == "disable":
            staff.disable(c, _user(c, args[0])["id"], BY)
            print(f"{args[0]} disabled; sessions ended")
        elif cmd == "enable":
            staff.enable(c, _user(c, args[0])["id"], BY)
            print(f"{args[0]} enabled")
        elif cmd == "list":
            for u in staff.listing(c):
                rs = ", ".join(f"{r['role']}[{r['line']}/{r['material']}{'' if r['port'] else '/no port'}]"
                               for r in u["roles"])  # fmt: skip
                state = "disabled" if u["disabled"] else ("active" if u["active"] else "not enrolled")
                print(f"{u['username']:<28} {u['name']:<24} {state:<13} {u['passkeys']} passkey(s)  {rs}")
        else:
            sys.exit(__doc__)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except staff.StaffError as e:
        sys.exit(str(e))
