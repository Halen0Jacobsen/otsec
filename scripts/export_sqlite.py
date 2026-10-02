"""Export legacy SQLite data for an EMPTY, Flyway-initialized PostgreSQL database.

Reads SQLite in read-only mode. Review the output before loading with psql.
"""
import argparse
import math
import sqlite3
from pathlib import Path

TABLES = ("environments", "assets", "observations", "plans", "findings", "report_imports", "audit")


def literal(value):
    if value is None:
        return "NULL"
    if isinstance(value, (float, int)):
        if not math.isfinite(value):
            raise ValueError("Non-finite database value")
        return repr(value)
    if not isinstance(value, str) or "\0" in value:
        raise ValueError("Unsupported database value")
    return "'" + value.replace("'", "''") + "'"


def export(source):
    with sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True) as db:
        lines = ["\\set ON_ERROR_STOP on", "BEGIN;", "SET LOCAL standard_conforming_strings = on;"]
        for table in TABLES:
            lines.append(f"DO $$ BEGIN IF EXISTS (SELECT 1 FROM {table}) THEN RAISE EXCEPTION 'Destination must be empty: {table}'; END IF; END $$;")
        for table in TABLES:
            cursor = db.execute(f"SELECT * FROM {table}")
            columns = [column[0] for column in cursor.description]
            if any(not column.replace("_", "").isalnum() for column in columns):
                raise ValueError("Unexpected schema")
            for row in cursor:
                lines.append(f"INSERT INTO {table} ({','.join(columns)}) VALUES ({','.join(map(literal, row))});")
        lines += ["SELECT setval(pg_get_serial_sequence('audit','id'), COALESCE((SELECT MAX(id) FROM audit),1), EXISTS(SELECT 1 FROM audit));", "COMMIT;"]
        return "\n".join(lines) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    output = export(args.source)
    with args.destination.open("x", encoding="utf-8", newline="\n") as destination:
        destination.write(output)
