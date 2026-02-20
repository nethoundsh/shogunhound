# Security Policy

## Supported Versions

Only the latest published release is supported with security fixes.

## Reporting a Vulnerability

Please report vulnerabilities privately using one of the following channels:

- GitHub: private security advisory for this repository

Expected response SLA:

- Initial acknowledgement within 48 hours
- Follow-up and triage details after reproduction and impact assessment

Please do not open public issues for suspected security vulnerabilities.

## In Scope

- Authentication or authorization bypasses
- IP validation bypass allowing private/special-range queries
- Log injection or log tampering paths
- Cache poisoning or unsafe cache persistence behaviors
- Dependency vulnerabilities with CVSS score >= 7.0 that materially affect this project

## Out of Scope

- Issues requiring physical access to a host
- Vulnerabilities in third-party Shodan systems or APIs
- Rate-limit bypass requests (rate-limiting behavior is intentional by design)

## Disclosure Policy

This project follows coordinated disclosure. When warranted, we will request a CVE ID and publish remediation guidance in release notes. We also credit reporters in `CHANGELOG.md` (unless anonymity is requested).
