# Architecture: shogunhound

## Request Flow

```
MCP Client (Cursor / Claude / agent)
        |  stdin/stdout
        v
  cmd/server/main.go
        |  registers tools, wires dependencies
        v
  internal/handler/handler*.go
        |  validates input, checks cache
        |--> internal/validator  (IP/range validation)
        |--> internal/cache      (TTL JSON cache)
        |        | miss
        |        v
        |--> internal/shodan     (rate-limited Shodan API client)
        |        |
        |        v
        '--> internal/formatter  (pretty / markdown / json output)
                  |
                  v
            MCP tool result (text)
```

## Trust Boundaries

| Boundary | What crosses it |
|---|---|
| MCP client -> server | Tool name + arguments (untrusted strings) |
| Server -> Shodan API | IP/query (validated), API key from env only |
| Server -> filesystem | Cache file (bounded 100 entries), log file (append, mode 0600) |

## Rate Limiting

`internal/shodan/client.go` holds a process-wide `*rateLimiter`. All Shodan-backed methods (QueryHost, Count, Search, CVELookup, DNS, Alerts) gate through it. Tier (free ~= 1 req/s, paid ~= 10 req/s) is set at server startup via `SHODAN_TIER`. `max_workers` in bulk handlers controls Go concurrency but does not bypass pacing.

## Logging

`internal/handler/handler_helpers.go` — `logQuery()` and `logBatchQuery()` emit structured slog JSON after each tool call. Log path: `LOG_PATH` env or `~/shodan_queries.log`. Mode: `0600`.

## Cache Lifecycle

1. **Startup:** load from `CACHE_PATH` (default `~/.shodan_cache.json`). Corrupt JSON -> warn to stderr, start empty.
2. **Per query:** check TTL (24h). Cache hit -> return immediately. Miss -> call Shodan, store result.
3. **Eviction:** oldest `QueriedAt`; max 100 entries.
4. **Persistence:** temp file + atomic rename in same directory.
