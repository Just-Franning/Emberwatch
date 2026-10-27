"""Account administration on the command line - for example when the only administrator lost the authenticator and
the recovery codes. In the container:

    docker exec -it emberwatch emberwatch-admin users
    docker exec -it emberwatch emberwatch-admin reset-password <name>   (new one-time password, sessions end)
    docker exec -it emberwatch emberwatch-admin reset-2fa <name>        (authenticator is set up again at sign-in)
    docker exec -it emberwatch emberwatch-admin create-admin <name>     (new administrator with a one-time password)
    docker exec -it emberwatch emberwatch-admin enable|disable <name>

Without the wrapper: cd /app/backend && python -m app.admincli <command>. Every change is recorded in the audit log
(user "cli"). The running server notices ended sessions within 30 seconds.
"""
from __future__ import annotations

import argparse
import sys

from .auth import Auth
from .config import load
from .db import DB, open_path
from .i18n import AppError

CLI_USER = {"id": 0, "name": "cli"}


def _uid(db: DB, name: str) -> int:
    rows = db.query("SELECT id FROM users WHERE name=?", (name.strip().lower(),))
    if not rows:
        raise AppError("err.acct.not_found", 404)
    return int(rows[0]["id"])


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="emberwatch-admin", description="Emberwatch: manage accounts")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("users", help="list the accounts")
    for cmd, text in (("reset-password", "set a one-time password (to be changed at the next sign-in)"),
                      ("reset-2fa", "remove the second factor (set up again at the next sign-in)"),
                      ("create-admin", "create an administrator with a one-time password"),
                      ("enable", "enable an account"), ("disable", "disable an account and end its sessions")):
        sp = sub.add_parser(cmd, help=text)
        sp.add_argument("name")
    args = p.parse_args(argv)
    s = load()
    db = DB(open_path(s.data_dir))
    auth = Auth(s, db)
    lang = s.language
    try:
        if args.cmd == "users":
            rows = auth.list_users()
            print(f"{'name':<24} {'role':<7} {'2fa':<4} {'state':<9} last sign-in")
            for u in rows:
                state = "disabled" if u["disabled"] else "new pw" if u["must_change"] else "active"
                print(f"{u['name']:<24} {u['role']:<7} {'yes' if u['totp'] else 'no':<4} {state:<9} {u['last_login'] or '-'}")
            if not rows:
                print("(no accounts; the first one is created at the start with AUTH_MODE=password)")
        elif args.cmd == "reset-password":
            pw = auth.reset_password(_uid(db, args.name), CLI_USER, "cli")
            print(f"One-time password for {args.name}: {pw}\nIt must be changed at the next sign-in.")
        elif args.cmd == "reset-2fa":
            auth.reset_totp(_uid(db, args.name), CLI_USER, "cli")
            print(f"Second factor of {args.name} removed. It is set up again at the next sign-in.")
        elif args.cmd == "create-admin":
            user, pw = auth.create_user(args.name, "admin", CLI_USER, "cli")
            print(f"Administrator {user['name']} created. One-time password: {pw}")
        else:
            auth.update_user(_uid(db, args.name), CLI_USER, "cli", disabled=args.cmd == "disable")
            print(f"{args.name}: {'disabled, sessions ended' if args.cmd == 'disable' else 'enabled'}")
    except AppError as exc:
        print(exc.render(lang), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
