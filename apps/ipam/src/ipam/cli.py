from __future__ import annotations

import argparse
from pathlib import Path

import uvicorn

from ipam.config import load_settings
from ipam.database import build_engine, build_session_factory, init_db, session_scope
from ipam.main import create_app
from ipam.services.importer import import_summary_as_text, import_workbook
from ipam.services.validation import rebuild_validation_issues


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RKE2 IPAM utility commands")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init-db", help="Create the SQLite database schema")

    import_parser = subparsers.add_parser("import-workbook", help="Import an Excel workbook into the database")
    import_parser.add_argument("workbook", type=Path, help="Path to the Excel workbook to import")

    serve_parser = subparsers.add_parser("serve", help="Run the development web server")
    serve_parser.add_argument("--reload", action="store_true", help="Enable auto-reload")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    settings = load_settings()
    engine = build_engine(settings.database_url)
    session_factory = build_session_factory(engine=engine)

    if args.command == "init-db":
        init_db(engine)
        print(f"Initialized database: {settings.database_url}")
        return

    if args.command == "import-workbook":
        init_db(engine)
        with session_scope(session_factory) as session:
            summary = import_workbook(session, args.workbook)
            issue_count = rebuild_validation_issues(session)
            print(import_summary_as_text(summary))
            print(f"Validation issues: {issue_count}")
        return

    if args.command == "serve":
        uvicorn.run(
            create_app(settings=settings),
            host=settings.host,
            port=settings.port,
            reload=args.reload,
        )
        return

    parser.error(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
