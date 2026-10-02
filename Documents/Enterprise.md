# Java enterprise edition

The primary server is Java 21 / Spring Boot 4.0.8 with Spring MVC, JDBC, Spring Security and Flyway. The WCT dashboard remains HTML/CSS/JavaScript and is packaged in the executable JAR from its existing source directory. The Java server does not invoke Python or scanners. Python remains a legacy CLI and an optional one-time SQLite export utility.

## Build and local development

Install JDK 21 and Maven 3.9+. From the repository root:

```powershell
mvn verify
java -jar target/otsec-0.2.0.jar --spring.profiles.active=local
```

Open http://127.0.0.1:8080. The explicit `local` profile uses H2 at `data/otsec-java.mv.db`, binds to loopback, validates Host/Origin, and enables session CSRF protection. It has no user authentication. Do not proxy or expose this profile. Use `--server.port=8081` if the legacy server is still running. Never activate local and enterprise together.

## Enterprise configuration

The default profile is `enterprise`. Missing database/identity configuration stops startup. Provision PostgreSQL and Keycloak separately; this repository does not deploy them. Supply secrets through your secret manager or environment, never committed files:

| Variable | Purpose |
| --- | --- |
| OTSEC_DATABASE_URL | `jdbc:postgresql://db.example:5432/otsec?sslmode=verify-full` with trusted database CA configured |
| OTSEC_DATABASE_USER | Dedicated application/migration database account |
| OTSEC_DATABASE_PASSWORD | Database secret |
| OTSEC_OIDC_ISSUER | HTTPS Keycloak realm issuer, for example `https://identity.example/realms/otsec` |
| OTSEC_OIDC_CLIENT_ID | Confidential OIDC client |
| OTSEC_OIDC_CLIENT_SECRET | Client secret |
| OTSEC_PORT | Optional listener port, default 8080 |

Configure the Keycloak client for authorization-code login, exact redirect URI `https://otsec.example/login/oauth2/code/keycloak` and minimal scopes `openid profile`. Make `realm_access.roles` available in ID token or UserInfo through a client scope mapper. Create uppercase realm roles:

| Role | Access |
| --- | --- |
| VIEWER | Read dashboard, evidence and audit |
| OPERATOR | Read; import reports; create action proposals |
| ADMIN | Operator permissions; create environments |

Only recognized roles grant access. Authentication is browser OIDC login with a server session; bearer-token API clients are not implemented. Audit actors use the authenticated subject, not an operator-supplied identity. Environment separation controls scope and production action policy, not tenant-specific read access: authorized users can view all environments. CSRF is required for mutations in both profiles. No scanner or device action executes.

Run with `java -jar target/otsec-0.2.0.jar`. Terminate HTTPS either in embedded Tomcat using `server.ssl.*` keystore properties, or at a trusted reverse proxy. Enterprise requests are redirected to HTTPS and cookies are secure. Behind a proxy, explicitly configure `server.forward-headers-strategy=framework`, strip client-supplied Forwarded/X-Forwarded-* headers, and firewall the backend so only the trusted proxy can connect. Forwarded headers are not trusted by default. Do not weaken TLS to make a deployment test pass.

Flyway applies `src/main/resources/db/migration/V1__foundation.sql` before serving requests. Take database backups before future upgrades. Migration credentials need DDL permissions; least-privilege runtime/migration credential separation is a future deployment improvement. Back up PostgreSQL with your managed service or pg_dump, restore into an isolated database and validate before cutover. For local H2 backups stop Java before copying its database files.

## Existing Python data

Java never opens or overwrites the SQLite database. Keep it as a rollback source. For a small workspace, recreate environments and reimport original reports. This generates new IDs/history. To preserve existing IDs, normalized evidence, plans and audit in PostgreSQL:

1. Stop writers on the Python server and back up SQLite.
2. Start Java once against an empty PostgreSQL database so Flyway initializes the schema, then stop Java.
3. Run `python scripts/export_sqlite.py data/otsec.db data/migration.sql` (substitute your actual SQLite path).
4. Review the sensitive SQL file. Load with `psql --dbname=your-secure-connection -f data/migration.sql`. Supply credentials through your approved mechanism. The script refuses nonempty application tables and rolls back on errors.
5. Compare all seven table counts and sample evidence/audit before restarting Java. Retain the SQLite backup and securely remove the export when finished.

Export reads SQLite in read-only mode and refuses to overwrite an existing output. Legacy audit actors remain legacy actors. The SQL is PostgreSQL-specific; direct SQLite-to-H2 migration is not provided. Migration does not retroactively authenticate legacy history or change its finding hashes. Reimporting old evidence after cutover can create duplicate rows because Java uses a new normalization/hash encoding; compare evidence before reimporting historical files.

## API and source map

Existing API payloads and snapshots remain compatible; see [API](API.md) and [integration contracts](IntegrationContracts.md). Java adds `GET /api/csrf`, returning `headerName` and `token`. Send the token as the named header with the same session cookie on POST. The shared dashboard automatically retrieves it. Request envelopes are bounded to 6 MiB; decoded report content to 5 MiB, and records/findings to 10,000. Invalid imports roll back evidence and audit writes together. Imports lock their environment row to serialize concurrent deduplication. Reports remain offline and originals are discarded.

| Source | Responsibility |
| --- | --- |
| OtsecApplication | Spring Boot entry point |
| ApiController | Existing API routes and validation errors |
| OtsecService | Scoped persistence, imports, proposals, snapshots and audit |
| ReportParser | Bounded JSON/XML normalization; XXE protection and ZAP URL redaction |
| Scope | Literal IP parsing and canonical CIDR checks without DNS lookup |
| SecurityConfig | Local CSRF and enterprise OIDC/role authorization |
| RequestBoundary | Request size limits and local Host/Origin boundary |
| resources/tools.json | Packaged integration catalog; update alongside Python registry while legacy CLI remains |
| resources/db/migration | Versioned database schema |

## Validation and remaining release work

`mvn verify` exercises all supported report formats, redaction, hostile XML, malformed atomic imports, deduplication, CIDR policy, production blocking, CSRF, role restrictions, HTTPS redirects and authenticated audit subjects using H2 and a stub OIDC registration. `python -m unittest discover -s tooling/tests -v` with PYTHONPATH=tooling checks legacy compatibility. GitLab CI runs both suites and packages the executable JAR.

Live PostgreSQL, real Keycloak login/role mapping, proxy TLS deployment, migration cutover and hosted CI require deployment verification. No high availability, tenant authorization, scheduler, live collection, MQTT/device provisioning, scanner execution, remediation execution or immutable external audit retention is delivered by this port. H2 development verification does not replace PostgreSQL testing.

References: [Spring Boot](https://docs.spring.io/spring-boot/4.0/index.html), [Spring Security OIDC](https://docs.spring.io/spring-security/reference/servlet/oauth2/login/core.html), [CSRF](https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html).
