# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.5] - 2026-02-20

### Fixed

- Replaced per-request post-call sleep pacing with a process-wide, context-aware token limiter to prevent free-tier overrun under bulk concurrency
- Extended process-wide limiter coverage across Shodan API methods (`Count`, `Search`, DNS, alert APIs, and exploit search), not only host queries
- Bulk/report worker paths now use shared startup tier pacing; backward-compatible `tier` parameters remain accepted but ignored
- Markdown formatters now escape table-breaking characters (`|`) and collapse embedded newlines in rendered fields
- Added RFC 3849 documentation IPv6 range (`2001:db8::/32`) to rejected non-public validation ranges
- Removed unused `DefaultTier` and `currentTier` methods from `ShodanClient`

## [0.1.3] - 2026-02-20

### Fixed

- `formatTagsWithContext` now annotates `cloud` tags with provider-context guidance (was falling through to raw tag)
- `FormatSearchResult(nil, "json")` now returns `{}` instead of empty string
- `formatSearchResultPretty` uses fixed-width column padding for consistent alignment
- `dateWithAge` tightened "recent" threshold to 14 days; month rounding uses `math.Round` for accuracy
- `initComponents` refactored to accept a `runtimeConfig` struct, eliminating duplicated env-var parsing
- `ipBulkTool` MCP description expanded with format guidance and follow-up workflow hints

## [0.1.2] - 2026-02-20

### Changed

- Added `--help` support and startup self-check diagnostics in the MCP server binary
- Expanded README with compatibility, tier behavior, JSON contract, and log rotation guidance
- Clarified release workflow/docs to match Linux release artifacts and GHCR publishing behavior

### Fixed

- Added summary audit logging for bulk/report operations and success logging for alert operations
- `shodan_report` now uses the server default tier instead of hardcoding `free`
- `shodan_report` now validates `format` (`markdown` or `json`) and returns a clear error for invalid values
- Added test and vet gates to the release workflow before artifact publishing
- Added outer timeout guard for CVE lookup to cap end-to-end request latency

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
