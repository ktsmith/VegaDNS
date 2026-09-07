# Security remediation map

The changes require the migration and deployment steps in INSTALL and UPGRADE.
All database values pass through bound PDO statements; dynamic SQL identifiers
come from fixed code or explicit allowlists. Web requests never create schema or
accounts. Error pages omit SQL, passwords, credentials and exception details.

| Finding | Implemented control | Regression evidence |
| --- | --- | --- |
| F-001 | DB bound values; Store scoped queries and fixed sort maps; typed IDs; defaults rebound when copied | SQL payloads in login, IDs, sorting, TXT insert/update and copied defaults |
| F-002 | Store record lookup/edit/delete scopes both domain_id and record_id; SOA deletion prohibited | Cross-tenant view/delete and SOA rejection, preserved foreign row |
| F-003 | DNS validates owner syntax and zone boundary at write/export; native wire encoding; publisher compiles before replacement | Malformed owner rejection, TXT one-line invariant, type round trips, invalid legacy export rejection |
| F-004 | View escapes text and attributes; URL query encoding; fixed route; restrictive CSP | Stored record/name markup and form attribute checks; HTTP rendering |
| F-005 | Strict cookie-only sessions, Secure/HttpOnly/SameSite, login/reset rotation; live account version checks | File/database HTTP sessions, fixation rejection, reset/deletion revocation |
| F-006 | Network uses proc_open argument arrays, validated zone/destination, bounded private transfer files | Shell syntax rejected before resolution; full process/tool compatibility requires target deployment |
| F-007 | Credential writers use POST; reject URL passwords and session IDs; never echo passwords | HTTP GET rejection, form encoding and CSRF checks |
| F-008 | Separate CLI migration/provisioning, no default account or automatic authentication | Empty schema contains no accounts; named operator provisioning required |
| F-009 | Public helper retired; authenticated senior-only transfer; IP allowlist/pinning and process limits | Tenant import denied before network; unapproved literal destination denied |
| F-010 | Random 256-bit reset proof, digest-only DB storage, expiry and atomic consumption; password_hash and legacy upgrade; shared rate counters | No change on request, successful redemption, replay/expiry rejection, version revocation, legacy upgrade |
| F-011 | POST and session CSRF on all mutations, Origin validation when supplied | Missing/wrong tokens and GET mutation rejected, valid form flows |
| F-012 | PHP 8.4+ platform manifest; removed vendored Smarty/Net_IPv6; native views/inet_pton | PHP lint, rendering and IPv4/IPv6/SRV encoding tests; no third-party dependency lock needed |
| F-013 | Removed missing/dead include paths; fail-closed entry point; runtime/webserver examples and isolated test harness | tests/security.php and tests/http_security.py; actual MySQL migration, TLS/proxy, mail and DNS compiler acceptance remain operator checks |
| F-014 | Transactional account deletion/ownership reassignment; live account/session-version enforcement | Deleted account cannot authenticate or retain its existing session |

Run `php tests/security.php` and `python3 tests/http_security.py php` locally.
The database tests also accept an explicitly named, empty MySQL vegadns_test
database. HTTP tests use disposable SQLite through both session handlers; they
do not validate MySQL wire behavior, actual TLS, mail delivery or tinydns tools.
The CI workflow runs database checks on MySQL as well as SQLite.
`sh tests/publisher.sh` checks download/empty-output/compiler failure handling
using fake curl and compiler processes. It does not validate the tinydns format.

Deployment actions cannot be completed by applying a source patch alone: configure
TLS/egress/secrets/private storage, migrate a backed-up database, test your DNS
toolchain and rotate any credentials exposed through historical logs. The legacy
UI is replaced; template customizations and import override behavior need review.
