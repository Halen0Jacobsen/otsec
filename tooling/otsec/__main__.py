import argparse
import json
import sys
from pathlib import Path

from .core import MAX_IMPORT, Store


def main():
    parser = argparse.ArgumentParser(description="OTSec local tooling companion")
    parser.add_argument("--db", default="data/otsec.db")
    commands = parser.add_subparsers(dest="command", required=True)
    env = commands.add_parser("environment", help="Register an isolated lab or production scope")
    env.add_argument("name")
    env.add_argument("--mode", choices=("lab", "production"), required=True)
    env.add_argument("--cidr", required=True)
    ingest = commands.add_parser("import-zeek", help="Import JSONL conn.log atomically")
    ingest.add_argument("environment")
    ingest.add_argument("file", type=Path)
    report = commands.add_parser("import-report", help="Normalize an external security tool report")
    report.add_argument("environment")
    report.add_argument("--tool", required=True)
    report.add_argument("--application", required=True)
    report.add_argument("file", type=Path)
    plan = commands.add_parser("plan", help="Create a proposal; never executes a tool")
    plan.add_argument("environment")
    plan.add_argument("--tool", required=True)
    plan.add_argument("--action", choices=("scan", "remediate"), required=True)
    plan.add_argument("--target", required=True)
    commands.add_parser("status")
    serve = commands.add_parser("serve", help="Local loopback operator workspace")
    serve.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    if args.command == "serve":
        from .server import serve as run_server
        run_server(args.db, args.port)
        return
    store = Store(args.db)
    try:
        if args.command == "environment":
            result = store.add_environment(args.name, args.mode, args.cidr)
        elif args.command == "import-zeek":
            with args.file.open("rb") as source:
                result = store.import_zeek(args.environment, source.read(MAX_IMPORT + 1))
        elif args.command == "plan":
            result = store.plan(args.environment, args.tool, args.action, args.target)
        elif args.command == "import-report":
            with args.file.open("rb") as source:
                result = store.import_report(args.environment, args.tool, args.application, source.read(MAX_IMPORT + 1))
        else:
            result = store.snapshot()
        print(json.dumps(result, indent=2))
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2) from None
    finally:
        store.close()


if __name__ == "__main__":
    main()
