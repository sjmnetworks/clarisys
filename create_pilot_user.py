#!/usr/bin/env python3
"""
Create a pilot user with a local API key.

Usage:
    python create_pilot_user.py --username alice --email alice@example.com
    python create_pilot_user.py --username alice --email alice@example.com --scopes firewall.evaluate firewall.read
    python create_pilot_user.py --list
    python create_pilot_user.py --disable alice

The generated API key is printed once and never stored. Keep it safe.
Pass it in the X-API-Key header when calling the API:

    curl -H "X-API-Key: <key>" http://localhost:8000/health
"""
from __future__ import annotations

import argparse
import secrets
import sys

# Ensure the project root is on the path when run directly
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))

from api.pilot_users import VALID_SCOPES, add_user, disable_user, list_users

DEFAULT_SCOPES = ["firewall.evaluate", "firewall.read"]


def cmd_create(args: argparse.Namespace) -> None:
    scopes = args.scopes or DEFAULT_SCOPES
    unknown = set(scopes) - VALID_SCOPES
    if unknown:
        print(f"ERROR: Unknown scope(s): {unknown}", file=sys.stderr)
        print(f"       Valid scopes: {sorted(VALID_SCOPES)}", file=sys.stderr)
        sys.exit(1)

    raw_key = secrets.token_urlsafe(32)
    add_user(
        username=args.username,
        email=args.email,
        raw_key=raw_key,
        scopes=scopes,
    )

    print()
    print("=" * 60)
    print(f"  Pilot user created: {args.username} <{args.email}>")
    print(f"  Scopes:             {', '.join(sorted(scopes))}")
    print()
    print(f"  API Key (copy now — it will NOT be shown again):")
    print(f"  {raw_key}")
    print("=" * 60)
    print()
    print("Usage:")
    print(f"  curl -H \"X-API-Key: {raw_key}\" http://localhost:8000/health")
    print()


def cmd_list(_args: argparse.Namespace) -> None:
    users = list_users()
    if not users:
        print("No pilot users found.")
        return
    print(f"{'USERNAME':<20} {'EMAIL':<30} {'ENABLED':<8} {'SCOPES'}")
    print("-" * 80)
    for u in users:
        print(
            f"{u['username']:<20} {u.get('email', ''):<30} "
            f"{'yes' if u.get('enabled', True) else 'no':<8} "
            f"{', '.join(u.get('scopes', []))}"
        )


def cmd_disable(args: argparse.Namespace) -> None:
    if disable_user(args.username):
        print(f"User '{args.username}' disabled.")
    else:
        print(f"User '{args.username}' not found.", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Manage pilot users for the OPA Firewall Policy API."
    )
    sub = parser.add_subparsers(dest="command")

    # create
    p_create = sub.add_parser("create", help="Create a new pilot user")
    p_create.add_argument("--username", required=True, help="Unique username")
    p_create.add_argument("--email", required=True, help="User email address")
    p_create.add_argument(
        "--scopes",
        nargs="+",
        metavar="SCOPE",
        help=f"Space-separated scopes (default: {DEFAULT_SCOPES}). "
             f"Valid: {sorted(VALID_SCOPES)}",
    )

    # list
    sub.add_parser("list", help="List all pilot users")

    # disable
    p_dis = sub.add_parser("disable", help="Disable a pilot user")
    p_dis.add_argument("username", help="Username to disable")

    # Legacy flat flags (--username / --list / --disable) for convenience
    parser.add_argument("--username", help=argparse.SUPPRESS)
    parser.add_argument("--email", help=argparse.SUPPRESS)
    parser.add_argument("--scopes", nargs="+", metavar="SCOPE", help=argparse.SUPPRESS)
    parser.add_argument("--list", action="store_true", help="List all pilot users")
    parser.add_argument("--disable", metavar="USERNAME", help="Disable a pilot user")

    args = parser.parse_args()

    # Legacy flat-flag mode
    if args.command is None:
        if args.list:
            cmd_list(args)
        elif args.disable:
            args.username = args.disable
            cmd_disable(args)
        elif args.username and args.email:
            cmd_create(args)
        else:
            parser.print_help()
            sys.exit(1)
        return

    dispatch = {"create": cmd_create, "list": cmd_list, "disable": cmd_disable}
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
