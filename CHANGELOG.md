# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-02-20

### Fixed

- golangci-lint-action upgraded to v7 (v6 incompatible with golangci-lint v2)
- golangci-lint pinned to latest to resolve Go 1.26 toolchain panic
- Release build matrix restricted to linux-amd64 and linux-arm64

## [0.1.0] - 2026-02-17

### Added

- Initial release: MCP stdio server with 11 Shodan tools
- shodan_ip_query, shodan_count, shodan_search, shodan_dns_resolve, shodan_dns_reverse
- shodan_ip_query_bulk, shodan_cve_lookup, shodan_report
- shodan_alert_create, shodan_alert_list, shodan_alert_delete
- investigate_ip and recon MCP prompts
- Local JSON cache with atomic writes and 24h TTL
- Structured JSON audit log
- IP validation rejecting all private/reserved/special ranges
- Multi-stage distroless Docker image published to GHCR
- Tag-triggered GitHub Actions release workflow (linux-amd64, linux-arm64)
