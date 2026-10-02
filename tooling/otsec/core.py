"""Validated configuration, passive discovery, policy planning and audit storage."""
import hashlib
import ipaddress
import json
import math
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .adapters import catalog, get_adapter

MAX_IMPORT = 5 * 1024 * 1024
MAX_RECORDS = 10000


def now():
    return datetime.now(timezone.utc).isoformat()


def label(value, field="name"):
    if not isinstance(value, str) or not value.strip() or len(value) > 120 or any(ord(c) < 32 for c in value):
        raise ValueError(f"{field} must contain 1–120 printable characters")
    return value.strip()


def network(value):
    try:
        return str(ipaddress.ip_network(value, strict=True))
    except (ValueError, TypeError):
        raise ValueError("Provide a canonical network CIDR, such as 192.168.10.0/24") from None


class Store:
    def __init__(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS environments (
            id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
            mode TEXT NOT NULL CHECK(mode IN ('lab','production')), cidr TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS assets (
            environment_id TEXT REFERENCES environments(id), ip TEXT NOT NULL,
            first_seen REAL NOT NULL, last_seen REAL NOT NULL,
            PRIMARY KEY(environment_id,ip));
          CREATE TABLE IF NOT EXISTS observations (
            id TEXT PRIMARY KEY, environment_id TEXT REFERENCES environments(id),
            ts REAL NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL,
            port INTEGER NOT NULL, service TEXT NOT NULL, external INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS plans (
            id TEXT PRIMARY KEY, environment_id TEXT REFERENCES environments(id),
            tool TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
            state TEXT NOT NULL, created_at TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL,
            resource TEXT NOT NULL, result TEXT NOT NULL, timestamp TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY, environment_id TEXT REFERENCES environments(id),
            tool TEXT NOT NULL, application TEXT NOT NULL, title TEXT NOT NULL,
            severity TEXT NOT NULL, resource TEXT NOT NULL, rule TEXT NOT NULL,
            description TEXT NOT NULL, solution TEXT NOT NULL, imported_at TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS report_imports (
            id TEXT PRIMARY KEY, environment_id TEXT REFERENCES environments(id),
            tool TEXT NOT NULL, application TEXT NOT NULL, findings INTEGER NOT NULL,
            duplicates INTEGER NOT NULL, imported_at TEXT NOT NULL);
        """)

    def close(self):
        self.db.close()

    def audit(self, action, resource, result="success"):
        self.db.execute("INSERT INTO audit(actor,action,resource,result,timestamp) VALUES(?,?,?,?,?)",
                        ("local-operator", action, resource, result, now()))

    def environment(self, name):
        name = label(name, "environment")
        row = self.db.execute("SELECT * FROM environments WHERE name=?", (name,)).fetchone()
        if row is None:
            raise ValueError("Unknown environment")
        return dict(row)

    def add_environment(self, name, mode, cidr):
        name, cidr = label(name), network(cidr)
        if mode not in ("lab", "production"):
            raise ValueError("Mode must be lab or production")
        identifier = str(uuid4())
        try:
            with self.db:
                self.db.execute("INSERT INTO environments VALUES(?,?,?,?)", (identifier, name, mode, cidr))
                self.audit("environment.create", identifier)
        except sqlite3.IntegrityError:
            raise ValueError("Environment name already exists") from None
        return self.environment(name)

    def import_zeek(self, environment, content):
        env = self.environment(environment)
        if not isinstance(content, bytes) or len(content) > MAX_IMPORT:
            raise ValueError("Import exceeds 5 MiB limit")
        scope = ipaddress.ip_network(env["cidr"])
        records = []
        try:
            lines = content.decode("utf-8").splitlines()
            for number, line in enumerate(lines, 1):
                if not line.strip():
                    continue
                if len(line) > 65536 or len(records) >= MAX_RECORDS:
                    raise ValueError("Import record or line limit exceeded")
                item = json.loads(line)
                if not isinstance(item, dict):
                    raise ValueError("Expected a JSON object")
                src = str(ipaddress.ip_address(item["id.orig_h"]))
                dst = str(ipaddress.ip_address(item["id.resp_h"]))
                ts = item["ts"]
                port = item["id.resp_p"]
                if type(ts) not in (int, float) or not math.isfinite(ts) or not 0 <= ts <= 253402300799:
                    raise ValueError("Invalid timestamp")
                if type(port) is not int or not 0 <= port <= 65535:
                    raise ValueError("Invalid port")
                service = label(item.get("service", "unknown"), "service")
                if ipaddress.ip_address(src) not in scope and ipaddress.ip_address(dst) not in scope:
                    raise ValueError("Observation has no endpoint in environment scope")
                normalized = (float(ts), src, dst, port, service)
                identifier = hashlib.sha256(json.dumps([env["id"], *normalized]).encode()).hexdigest()
                records.append((identifier, *normalized))
        except (UnicodeError, KeyError, TypeError, ValueError, RecursionError) as error:
            raise ValueError(f"Invalid Zeek import near line {locals().get('number', 1)}; no records imported") from error
        if not records:
            raise ValueError("Import contains no observations")
        imported = 0
        with self.db:
            for identifier, ts, src, dst, port, service in records:
                external = int(ipaddress.ip_address(src) not in scope or ipaddress.ip_address(dst) not in scope)
                cursor = self.db.execute("INSERT OR IGNORE INTO observations VALUES(?,?,?,?,?,?,?,?)",
                                         (identifier, env["id"], ts, src, dst, port, service, external))
                imported += cursor.rowcount
                for address in (src, dst):
                    if ipaddress.ip_address(address) in scope:
                        self.db.execute("""INSERT INTO assets VALUES(?,?,?,?)
                          ON CONFLICT(environment_id,ip) DO UPDATE SET
                          first_seen=min(first_seen,excluded.first_seen), last_seen=max(last_seen,excluded.last_seen)""",
                                        (env["id"], address, ts, ts))
            self.audit("zeek.import", env["id"], f"imported:{imported};duplicates:{len(records)-imported}")
        return {"imported": imported, "duplicates": len(records)-imported}

    def plan(self, environment, tool, action, target):
        env = self.environment(environment)
        adapter = get_adapter(tool)
        target = str(ipaddress.ip_address(label(target, "target")))
        if ipaddress.ip_address(target) not in ipaddress.ip_network(env["cidr"]):
            raise ValueError("Target is outside the environment allowlist")
        if action not in ("scan", "remediate"):
            raise ValueError("Action must be scan or remediate")
        required = "application-scan" if action == "scan" else "remediation-proposal"
        if adapter.capability != required:
            raise ValueError("Adapter does not support this action")
        identifier = str(uuid4())
        state = "blocked-by-policy" if env["mode"] == "production" and action == "scan" else "proposed"
        with self.db:
            self.db.execute("INSERT INTO plans VALUES(?,?,?,?,?,?,?)",
                            (identifier, env["id"], tool, action, target, state, now()))
            self.audit("plan.create", identifier, state)
        return {"id": identifier, "state": state, "executed": False}

    def import_report(self, environment, tool, application, content):
        from .reports import normalize
        env = self.environment(environment)
        adapter = get_adapter(tool)
        if adapter.status != "report-import":
            raise ValueError("This tool does not support report imports")
        application = label(application, "application")
        records = normalize(tool, content)
        imported = 0
        with self.db:
            for row in records:
                identifier = hashlib.sha256(json.dumps([env["id"], tool, application, row], sort_keys=True).encode()).hexdigest()
                cursor = self.db.execute("INSERT OR IGNORE INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (identifier, env["id"], tool, application, row["title"], row["severity"], row["resource"], row["rule"], row["description"], row["solution"], now()))
                imported += cursor.rowcount
            report_id = str(uuid4())
            self.db.execute("INSERT INTO report_imports VALUES(?,?,?,?,?,?,?)", (report_id, env["id"], tool, application, imported, len(records)-imported, now()))
            self.audit("report.import", report_id, f"imported:{imported};duplicates:{len(records)-imported}")
        return {"imported": imported, "duplicates": len(records)-imported, "report_id": report_id}

    def snapshot(self):
        def rows(query):
            return [dict(row) for row in self.db.execute(query)]
        return {
            "environments": rows("SELECT * FROM environments ORDER BY name"),
            "assets": rows("SELECT a.*,e.name environment FROM assets a JOIN environments e ON e.id=a.environment_id ORDER BY e.name,a.ip LIMIT 500"),
            "observations": rows("SELECT o.*,e.name environment FROM observations o JOIN environments e ON e.id=o.environment_id ORDER BY ts DESC LIMIT 100"),
            "plans": rows("SELECT p.*,e.name environment FROM plans p JOIN environments e ON e.id=p.environment_id ORDER BY created_at DESC LIMIT 100"),
            "audit": rows("SELECT * FROM audit ORDER BY id DESC LIMIT 100"),
            "tools": catalog(),
            "findings": rows("SELECT f.*,e.name environment FROM findings f JOIN environments e ON e.id=f.environment_id ORDER BY imported_at DESC LIMIT 500"),
            "report_imports": rows("SELECT r.*,e.name environment FROM report_imports r JOIN environments e ON e.id=r.environment_id ORDER BY imported_at DESC LIMIT 100"),
            "severity_counts": dict(self.db.execute("SELECT severity,count(*) FROM findings GROUP BY severity").fetchall()),
            "counts": {table: self.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                       for table in ("assets", "observations", "plans", "environments", "findings", "report_imports")},
        }
