# Implementation Tasks for shogunhound

Ordered by priority and dependency. Each task specifies what to change, which file and line, and the correct behavior.

---

## Task 1 — Fix UTF-8 banner truncation (formatter.go)

**File:** `internal/formatter/formatter.go:122-124`
**Problem:** `text[:200]` is a byte-slice truncation. Multi-byte UTF-8 characters can be split, producing an invalid string.
**Fix:** Add a `truncateRunes(s string, n int) string` helper that truncates by rune count. Replace `text[:200] + "…"` with `truncateRunes(text, 200) + "…"`.

```go
func truncateRunes(s string, n int) string {
    r := []rune(s)
    if len(r) <= n {
        return s
    }
    return string(r[:n])
}
```

---

## Task 2 — Strip raw error from humanizeError default case (handler.go)

**File:** `internal/handler/handler.go:267-268` and `282-283`
**Problem:** Both `humanizeError` and `humanizeSearchError` default cases include `err.Error()` in the message returned to the LLM. This can expose internal go-shodan library details.
**Fix:** Return a generic message to the caller; log the raw error using `h.logger` (or `slog.Default()`). The default branch should become:
```go
default:
    return "Shodan API error; try again later"
```
The raw error is already captured in `logQuery` calls upstream for `HandleShodanIPQuery`. For `HandleShodanSearch` and DNS handlers, add a `slog.Error` call before returning the error result so the raw message is preserved in logs.

---

## Task 3 — Add Close() method to ToolHandler (handler.go)

**File:** `internal/handler/handler.go`
**Problem:** The log file opened in `New()` is never closed. Log rotation requires a server restart.
**Fix:**
1. Add `logFile *os.File` field to `ToolHandler` struct.
2. Store the `logFile` reference in `New()`.
3. Add a `Close() error` method that calls `h.logFile.Close()`.
4. In `cmd/server/main.go`, call `defer handler.Close()` after the handler is created.

---

## Task 4 — Fix rate-limit sleep to use a fresh context (shodan/client.go)

**File:** `internal/shodan/client.go:68-70`
**Problem:** `sleepWithContext` is called with the same 4-second context as the HTTP call. If the HTTP response arrives near the deadline, the sleep returns `DeadlineExceeded` even though the fetch succeeded, causing the caller to report a timeout on a successful result.
**Fix:** After a successful HTTP fetch, call `sleepWithContext` with `context.Background()` and a fixed timeout equal to the rate-limit delay + a small buffer (e.g. 200ms):
```go
sleepCtx, sleepCancel := context.WithTimeout(context.Background(), rateLimitDelay(c.tier)+200*time.Millisecond)
defer sleepCancel()
if err := sleepWithContext(sleepCtx, rateLimitDelay(c.tier)); err != nil {
    // Sleep interrupted (server shutdown), ignore — result is valid.
    return result, nil
}
```
Remove the comment noting the known issue once fixed.

---

## Task 5 — Add cache version validation on load (cache/cache.go)

**File:** `internal/cache/cache.go:167-185` (`load` function)
**Problem:** `cacheVersion` is written to disk but never checked on load. A schema change would silently produce corrupt data.
**Fix:** After unmarshalling, check `payload.Version != cacheVersion`. If mismatched, discard entries and log a warning to stderr:
```go
if payload.Version != cacheVersion {
    fmt.Fprintf(os.Stderr, "warning: cache version mismatch (got %d, want %d); discarding cache\n", payload.Version, cacheVersion)
    c.entries = make(map[string]Entry)
    return nil
}
```

---

## Task 6 — Add ~username comment to expandPath (cache/cache.go)

**File:** `internal/cache/cache.go:187-208` (`expandPath` function)
**Problem:** `expandPath` handles `~/` but not `~username/` style paths. Not a bug in practice, but worth documenting.
**Fix:** Add a single comment above the `~` check:
```go
// Note: only bare ~ and ~/ are expanded. ~username/ paths are not supported.
```

---

## Task 7 — Fix slow eviction test (cache/cache_test.go)

**File:** `internal/cache/cache_test.go:127-147` (`TestCacheEvictsOldestAfter100Entries`)
**Problem:** The test uses `time.Sleep(1ms)` between 101 inserts to guarantee distinct `QueriedAt` timestamps. This adds ~100ms and forces the test to be non-parallel.
**Fix:** Bypass `Set()` and write directly to `c.entries` with manually incremented timestamps, similar to the other cache tests. Use `Set()` only for the 101st entry (the one that triggers eviction). Mark the test `t.Parallel()`.

---

## Task 8 — Add mapAPIError brittleness test (shodan/client_test.go)

**File:** `internal/shodan/client_test.go`
**Problem:** `mapAPIError` matches on error message strings from go-shodan. If the library changes its wording, the sentinels silently stop matching.
**Fix:** Add a unit test that directly calls `mapAPIError` with the exact string patterns currently relied upon and asserts the expected sentinel error is returned. This test will fail if go-shodan changes its error messages, providing an early warning.

```go
func TestMapAPIErrorSentinels(t *testing.T) {
    cases := []struct {
        input    string
        expected error
    }{
        {"401 Unauthorized", ErrUnauthorized},
        {"invalid api key", ErrUnauthorized},
        {"429 Too Many Requests", ErrRateLimited},
        {"rate limit reached", ErrRateLimited},
        {"404 Not Found", ErrNotFound},
        {"no information available for that ip", ErrNotFound},
    }
    for _, tc := range cases {
        err := mapAPIError(fmt.Errorf(tc.input))
        if !errors.Is(err, tc.expected) {
            t.Errorf("mapAPIError(%q) = %v, want %v", tc.input, err, tc.expected)
        }
    }
}
```

---

## Task 9 — Handler unit tests (internal/handler/handler_test.go — new file)

**File:** `internal/handler/handler_test.go` (create new)
**Problem:** No tests exist for handler.go. The handler owns parameter extraction, cache integration, error humanization, and audit logging.

**Tests to write:**

**9a. Helper function tests (no I/O needed):**
- `TestOptionalString` — missing key returns default; present key returns value; wrong type returns error; blank string returns default
- `TestOptionalBool` — missing key returns default; present true/false returns correctly; wrong type returns error
- `TestResolvePath` — empty path returns error; `~/foo` expands to home; absolute path returned as-is; `~` alone returns home dir

**9b. humanizeError / humanizeSearchError:**
- Each sentinel error (`ErrUnauthorized`, `ErrRateLimited`, `ErrNotFound`, `context.DeadlineExceeded`, unknown error) maps to the expected human-readable string.
- Verify the default case no longer includes raw error text (after Task 2 is applied).

**9c. HandleShodanIPQuery integration test (using fakes):**
- Define a minimal `shodanQuerier` interface in handler_test.go (`QueryHost(ctx, ip, history, minify) (*ShodanHostResult, error)`).
- Create a `fakeClient` stub that returns a canned result or a specified error.
- Create a `fakeCache` stub.
- Test: missing `ip` parameter → tool error; invalid IP → tool error; cache hit → cached result with note; cache miss + success → result written to cache; cache miss + ErrNotFound → tool error with correct message.

---

## Task 10 — Expand formatter tests (internal/formatter/formatter_test.go)

**File:** `internal/formatter/formatter_test.go`

**Tests to add:**

**10a. `FormatSearchResult` — all three formats:**
- pretty: contains header line, total count, at least one IP row
- markdown: produces a markdown table with correct headers
- json: valid JSON, `Total` field matches

**10b. `formatTagsWithContext`:**
- `honeypot` → contains "treat as decoy"
- `tor` → contains "Tor exit/relay node"
- `scanner` → contains "known scanning infrastructure"
- unknown tag → returned as-is
- empty slice → "(none)"

**10c. `dateWithAge`:**
- zero time → "(unknown)"
- date within 30 days → contains "(recent)"
- date 60 days ago → contains "days ago"
- date 120 days ago → contains "months ago - data may be stale"

**10d. Banner truncation (after Task 1):**
- Banner of 201 ASCII chars → truncated to 200 + "…"
- Banner with multi-byte UTF-8 (e.g. 199 ASCII chars + a 3-byte rune) → truncated correctly without producing invalid UTF-8

---

## Task 11 — Add GitHub Actions CI (new file)

**File:** `.github/workflows/ci.yml` (create new)
**Contents:**
- Trigger: push and pull_request on main
- Jobs: `test` (go test ./...) and `lint` (golangci-lint with at minimum `go vet` and `staticcheck`)
- Go version matrix: 1.21 and latest
- Add `govulncheck` step (fitting for a security tool)

---

## Task 12 — Add SHODAN_TIER environment variable support (cmd/server/main.go)

**File:** `cmd/server/main.go` (`initComponents` function)
**Problem:** The default tier is hardcoded to "free". There is no way to configure it without modifying the MCP tool call.
**Fix:** Read `os.Getenv("SHODAN_TIER")` in `initComponents`. If set to "paid", pass "paid" to `shodan.NewClient`. Update the Configuration table in README.md to document `SHODAN_TIER`.

---

## Task 13 — Document or remove deploy/shogunhound.service (README.md)

**File:** `README.md`, `deploy/shogunhound.service`
**Problem:** The systemd unit file exists but the README's Usage section makes no mention of it. It could confuse users.
**Fix:** Add a brief "Future: HTTP/SSE Deployment" subsection to Usage noting that the service file is experimental and not yet supported.

---

## Files to Create or Modify

| File | Action |
|------|--------|
| `internal/formatter/formatter.go` | Task 1 |
| `internal/formatter/formatter_test.go` | Task 10 |
| `internal/handler/handler.go` | Tasks 2, 3 |
| `internal/handler/handler_test.go` | Task 9 (new file) |
| `internal/shodan/client.go` | Task 4 |
| `internal/shodan/client_test.go` | Task 8 |
| `internal/cache/cache.go` | Tasks 5, 6 |
| `internal/cache/cache_test.go` | Task 7 |
| `cmd/server/main.go` | Tasks 3 (defer Close), 12 |
| `README.md` | Tasks 12, 13 |
| `.github/workflows/ci.yml` | Task 11 (new file) |

---

## Verification

After all tasks are complete:
```bash
go test ./...           # all packages pass, no new test failures
go vet ./...            # no vet issues
go build ./...          # compiles cleanly
```
Manually test: run `shogunhound` as an MCP server and confirm `shodan_ip_query` still returns valid results for a known IP (e.g. 8.8.8.8).
