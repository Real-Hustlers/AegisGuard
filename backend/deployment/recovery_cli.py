"""Source and PyInstaller entry point for enterprise recovery."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from backend.deployment.enterprise_recovery import (
    create_backup,
    default_paths,
    recover_interrupted_restore,
    restore_backup,
    verify_backup,
)


def _print(value):
    print(
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            default=str,
        )
    )


def _path(value, default):
    return Path(
        value
        if value is not None
        else default
    )


def main():
    defaults = default_paths()

    parser = argparse.ArgumentParser(
        prog="AegisGuardRecovery",
    )
    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    backup_command = commands.add_parser(
        "backup"
    )
    backup_command.add_argument(
        "--output",
        required=True,
    )
    backup_command.add_argument(
        "--analyzer-db",
    )
    backup_command.add_argument(
        "--collector-config",
    )
    backup_command.add_argument(
        "--collector-state",
    )
    backup_command.add_argument(
        "--ml-registry",
    )

    verify_command = commands.add_parser(
        "verify"
    )
    verify_command.add_argument(
        "--backup",
        required=True,
    )

    restore_command = commands.add_parser(
        "restore"
    )
    restore_command.add_argument(
        "--backup",
        required=True,
    )
    restore_command.add_argument(
        "--analyzer-db",
    )
    restore_command.add_argument(
        "--collector-config",
    )
    restore_command.add_argument(
        "--collector-state",
    )
    restore_command.add_argument(
        "--ml-registry",
    )
    restore_command.add_argument(
        "--apply",
        action="store_true",
    )
    restore_command.add_argument(
        "--services-stopped",
        action="store_true",
    )

    recover_command = commands.add_parser(
        "recover-transaction"
    )
    recover_command.add_argument(
        "--transaction-directory",
        required=True,
    )

    args = parser.parse_args()

    if args.command == "backup":
        result = create_backup(
            output=Path(
                args.output
            ),
            analyzer_db=_path(
                args.analyzer_db,
                defaults[
                    "analyzer_db"
                ],
            ),
            collector_config=_path(
                args.collector_config,
                defaults[
                    "collector_config"
                ],
            ),
            collector_state=_path(
                args.collector_state,
                defaults[
                    "collector_state"
                ],
            ),
            ml_registry=_path(
                args.ml_registry,
                defaults[
                    "ml_registry"
                ],
            ),
        )
        _print(result)
        return

    if args.command == "verify":
        _print(
            verify_backup(
                args.backup
            )
        )
        return

    if args.command == "restore":
        _print(
            restore_backup(
                backup=args.backup,
                analyzer_db=_path(
                    args.analyzer_db,
                    defaults[
                        "analyzer_db"
                    ],
                ),
                collector_config=_path(
                    args.collector_config,
                    defaults[
                        "collector_config"
                    ],
                ),
                collector_state=_path(
                    args.collector_state,
                    defaults[
                        "collector_state"
                    ],
                ),
                ml_registry=_path(
                    args.ml_registry,
                    defaults[
                        "ml_registry"
                    ],
                ),
                apply=bool(
                    args.apply
                ),
                services_stopped=bool(
                    args.services_stopped
                ),
            )
        )
        return

    if args.command == "recover-transaction":
        _print(
            recover_interrupted_restore(
                args.transaction_directory
            )
        )
        return

    raise RuntimeError(
        "unsupported recovery command"
    )


if __name__ == "__main__":
    main()
