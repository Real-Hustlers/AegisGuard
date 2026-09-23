"""Local operator CLI for provisioning AegisGuard application users."""

import argparse
import getpass
import sys

from backend.analyzer.database import get_connection
from backend.storage.user_auth import (
    UserAlreadyExistsError,
    UserAuthError,
    create_user,
)


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Create an AegisGuard application user locally. "
            "The password is prompted securely and is never accepted "
            "as a command-line argument."
        )
    )
    parser.add_argument("username")
    parser.add_argument(
        "--role",
        required=True,
        choices=("ADMINISTRATOR", "ANALYST", "VIEWER"),
    )
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    password = getpass.getpass("Password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        print("Passwords do not match.", file=sys.stderr)
        return 2

    conn = get_connection()
    try:
        user = create_user(
            conn,
            args.username,
            password,
            args.role,
        )
    except UserAlreadyExistsError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    except UserAuthError as exc:
        print(str(exc), file=sys.stderr)
        return 4
    finally:
        conn.close()

    print(
        "Created user "
        f"{user['username']} "
        f"({user['role']}) "
        f"id={user['user_id']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
