# OTSec documentation

Start with the repository [README](../README.md) to run the application.

| Document | Purpose |
| --- | --- |
| [Operations](Operations.md) | Installation, configuration, CLI commands, imports, persistence, backup and troubleshooting |
| [HTTP API](API.md) | Local routes, request/response contracts, validation and access boundaries |
| [Integration contracts](IntegrationContracts.md) | Supported report formats, severity mapping, deduplication and adapter limits |
| [Architecture and delivery gates](ToolingFoundation.md) | Current companion architecture, threat register, release targets and requirement status |
| [Current brand system](BrandSystem.md) | Authoritative WCT palette and UI conventions |
| [Verification](Verification.md) | Local check commands, test coverage, browser evidence and unverified areas |
| [Project purpose](ProjectPurpose.md) | Planned Spring Boot, PostgreSQL, Keycloak and Mosquitto platform |
| [Project scope](ProjectScope.md) | Overall platform scope and future extensions |
| [Project charter](ProjectCharter.md) | Original project charter |
| [Deliverables](ProjectDeliverables.md) | Overall planned deliverables |

Functional and security release targets remain in [Requirements](../Requirements).
The runnable Python companion is an initial implementation; it does not satisfy
all planned platform requirements. See [tooling source guide](../tooling/README.md)
for module responsibilities and [contribution guidance](../CONTRIBUTING.md) for changes.
