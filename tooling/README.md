# OTSec tooling companion

Python standard-library application with SQLite persistence, a local HTTP API,
and a browser UI. Run instructions are in the [root README](../README.md).

## Source map

| Path | Responsibility |
| --- | --- |
| `otsec/__main__.py` | CLI argument parsing and dispatch |
| `otsec/core.py` | Environment validation, transactions, passive asset discovery, proposals and audit |
| `otsec/reports.py` | Bounded normalization of ZAP, Dependency-Check, SpotBugs/Find Security Bugs and SonarQube reports |
| `otsec/adapters.py` | Explicit tool capability/status registry and setup guidance |
| `otsec/server.py` | Loopback HTTP routes, same-origin write checks and static-file allowlist |
| `otsec/web/index.html` | Workspace views and accessible forms/dialogs |
| `otsec/web/app.js` | UI rendering, filters, file imports and proposals using DOM textContent |
| `otsec/web/style.css` | Current Widespread Custom branding, local font definitions and responsive layout |
| `otsec/web/fonts/` | Bundled fonts and OFL license notices |
| `otsec/web/wcd-logo.png` | User-provided WCD logo |
| `examples/` | Synthetic connection and security reports; not real vulnerability evidence |
| `tests/` | Standard-library unittest regression suite |

## Extending a tool

1. Add explicit capability, implementation status, report format and setup guidance
   in `adapters.py`. Planned entries must not offer an import action.
2. Add validation and normalization in `reports.py` for report imports. Keep network
   and subprocess execution out of this parser. Retain only reviewed evidence fields.
3. Add valid-control and adverse-input tests in `tests/test_reports.py`; verify all
   rows validate before any database writes.
4. Update [integration contracts](../Documents/IntegrationContracts.md), setup
   guidance, supported limitations and the root README.

Execution workers, scanner installation, remote collectors, authenticated identity,
approvals, scheduling, rollback and production operation are future platform work.
An adapter entry alone does not connect or install a tool.
