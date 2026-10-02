# Java server operations

Use [Java enterprise edition](Enterprise.md) for current Java build, local H2, PostgreSQL, Keycloak, TLS, backups and SQLite migration. The instructions below document the preserved Python companion.

# Operating the local OTSec companion

## Requirements and startup

Use Python 3.11 or later. SQLite, HTTP serving and report parsing use the Python
standard library; no pip install is required. Node is optional for checking frontend
JavaScript syntax and is not needed to run the app. The application is tested on
Windows with Python 3.14; Linux/macOS commands are supplied but not runtime-verified.

Clone the repository, open a terminal at its root, then run:

```powershell
git clone https://gitlab.com/halenjacobsen/otsec.git
cd otsec
$env:PYTHONPATH = "$PWD/tooling"
python -m otsec serve
```

In Bash, replace the PowerShell environment assignment with:

```bash
export PYTHONPATH="$PWD/tooling"
```

Open `http://127.0.0.1:8080`. The exact address matters: the Host check does not
accept `localhost` aliases. Stop with Ctrl+C. The browser is not opened automatically.
Use `python -m otsec serve --port 8081` when the default port is already in use.
There is no configurable remote bind address.

## Configuration and data

`--db` is a global option and comes before the subcommand:

```powershell
python -m otsec --db data/lab.db serve --port 8081
```

The default database is `data/otsec.db`, relative to the terminal's current directory.
Missing parent directories and tables are created automatically. Existing rows are
retained. Tables are created with `CREATE TABLE IF NOT EXISTS`; no versioned migration
framework exists yet. Always start from the repository root for the documented path.

The local filesystem account owns the data. Database access, backups, logs and
retention require appropriate OS permissions. `data/`, `.env`, virtual environments,
Python caches and the existing local `zeek/` checkout are excluded from Git.
Do not put credentials or real imported reports in `tooling/examples`.

## Browser workflow

1. Add an environment with a unique name, `lab`/`production` policy and a canonical
   network CIDR. Use `192.168.10.0/24`, not a host address such as `192.168.10.15/24`.
   Environment settings are immutable in this version.
2. Import evidence from Overview, Environments, Findings or Integrations. Choose
   environment, source tool, application/project label and a UTF-8 report file.
   Zeek imports do not require an application label.
3. Review normalized findings with environment, tool, severity and search filters.
   Open a finding to inspect resource, rule, description and recommended action.
4. Create an IP-scoped ZAP scan or custom remediation proposal. Production scan
   proposals are recorded as blocked. Nothing executes or changes an OT device.
5. Review Plans & audit. Refresh data after external CLI changes. There is no polling.

The UI loads up to 500 assets/findings and 100 observations/plans/imports/audit
events. Global metrics use stored totals; filtered metrics represent loaded rows
and are labeled accordingly. Audit environment filtering matches loaded related
records and can omit older associated events.

## CLI reference

| Command | Inputs | Result |
| --- | --- | --- |
| `environment NAME --mode lab\|production --cidr CIDR` | Unique printable name up to 120 characters, canonical CIDR | Creates environment and audit record |
| `import-zeek ENV FILE` | Existing environment, UTF-8 JSONL conn.log | Atomic observations/assets import, duplicate count and audit |
| `import-report ENV --tool ID --application LABEL FILE` | Existing environment, supported tool ID, printable application label up to 120 characters | Atomic findings/history import and audit |
| `plan ENV --tool ID --action scan\|remediate --target IP` | Matching tool capability, literal target IP in CIDR | Proposed or blocked plan and audit; executed=false |
| `status` | Optional global `--db` | JSON snapshot with loaded records, counts, tools and severity totals |
| `serve --port PORT` | Optional global `--db`, port 1–65535 | Local operator HTTP workspace |

Report tool IDs: `zaproxy`, `dependency-check`, `spotbugs`, `find-sec-bugs`, `sonarqube`.
Plan combinations: `zaproxy` + `scan`, or `custom` + `remediate`.
Use `python -m otsec --help` and subcommand `--help` for exact argument syntax.
Successful CLI operations emit JSON. Handled validation/file errors exit with code 2.
Unexpected SQLite or server startup errors may emit a Python traceback.

## Examples

```powershell
python -m otsec environment lab --mode lab --cidr 192.168.10.0/24
python -m otsec environment plant --mode production --cidr 10.20.0.0/24
python -m otsec import-zeek lab tooling/examples/conn.jsonl
python -m otsec import-report lab --tool dependency-check --application "Demo API (synthetic)" tooling/examples/dependency-check-demo.json
python -m otsec import-report lab --tool zaproxy --application "Demo API (synthetic)" tooling/examples/zap-demo.json
python -m otsec import-report lab --tool find-sec-bugs --application "Demo API (synthetic)" tooling/examples/spotbugs-demo.xml
python -m otsec import-report lab --tool sonarqube --application "Demo API (synthetic)" tooling/examples/sonarqube-demo.json
python -m otsec plan plant --tool zaproxy --action scan --target 10.20.0.20
```

The final example produces `blocked-by-policy`. All example findings are synthetic.
Real report formats and normalization limits are documented in [Integration contracts](IntegrationContracts.md).

## Backup and recovery

Stop all OTSec processes using the selected database, then copy the database to an
access-controlled backup location. Do not commit backups. Restore only while the
app is stopped; retain the previous file until the restored copy has been checked.
Starting the same version against the restored database preserves records. There
is no UI deletion/reset, backup scheduler, encrypted database or retention job.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| `No module named otsec` | Set PYTHONPATH as above in the current terminal and run from repository root |
| Address already in use | Select another unused port; do not terminate an unidentified process |
| 403 in browser | Use the exact 127.0.0.1 URL/port; do not expose through a proxy |
| Unknown environment / duplicate name | Select an existing environment or use a unique new name |
| Report rejected | Check source adapter, UTF-8 encoding, documented schema and 5 MiB/10,000 finding limits |
| Zeek batch rejected | Every row needs a scoped endpoint, valid timestamp/IP/port and supported field types |
| Duplicate import reports zero new findings | Deduplication is expected; inspect existing findings and import history |
| No findings for a filter | Clear environment/tool/severity/search filters; only the latest 500 findings load |
| Database unable to open / locked | Check path/permissions and other processes; do not delete a database to fix the error |
| UI not reflecting CLI changes | Refresh data; reload the browser for changed CSS/JS |

No live telemetry, authenticated remote services or scanner installation is performed.
