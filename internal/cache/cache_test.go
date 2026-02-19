package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nethoundsh/shogunhound/internal/shodan"
)

func TestCacheGetHit(t *testing.T) {
	t.Parallel()

	cachePath := filepath.Join(t.TempDir(), "cache.json")
	c, err := New(cachePath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	want := &shodan.ShodanHostResult{IP: "8.8.8.8"}
	c.entries["8.8.8.8"] = Entry{
		QueriedAt: time.Now().Add(-1 * time.Hour),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Data:      want,
	}

	got, queriedAt, ok := c.Get("8.8.8.8")
	if !ok {
		t.Fatalf("Get() ok = false, want true")
	}
	if got == nil || got.IP != want.IP {
		t.Fatalf("Get() result = %#v, want IP=%s", got, want.IP)
	}
	if queriedAt.IsZero() {
		t.Fatalf("Get() queriedAt is zero, want non-zero")
	}
}

func TestCacheGetMissAbsent(t *testing.T) {
	t.Parallel()

	cachePath := filepath.Join(t.TempDir(), "cache.json")
	c, err := New(cachePath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	got, queriedAt, ok := c.Get("8.8.8.8")
	if ok || got != nil || !queriedAt.IsZero() {
		t.Fatalf("Get() = (%#v, %v, %v), want (nil, zero, false)", got, queriedAt, ok)
	}
}

func TestCacheGetMissExpired(t *testing.T) {
	t.Parallel()

	cachePath := filepath.Join(t.TempDir(), "cache.json")
	c, err := New(cachePath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	c.entries["8.8.8.8"] = Entry{
		QueriedAt: time.Now().Add(-26 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		Data:      &shodan.ShodanHostResult{IP: "8.8.8.8"},
	}

	got, queriedAt, ok := c.Get("8.8.8.8")
	if ok || got != nil || !queriedAt.IsZero() {
		t.Fatalf("Get() = (%#v, %v, %v), want (nil, zero, false)", got, queriedAt, ok)
	}
}

func TestCacheSetAndPersist(t *testing.T) {
	t.Parallel()

	cachePath := filepath.Join(t.TempDir(), "cache.json")
	c, err := New(cachePath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	c.Set("1.1.1.1", &shodan.ShodanHostResult{IP: "1.1.1.1", Organization: "Cloudflare"})

	c2, err := New(cachePath)
	if err != nil {
		t.Fatalf("New() second cache error = %v", err)
	}

	got, queriedAt, ok := c2.Get("1.1.1.1")
	if !ok {
		t.Fatalf("Get() ok = false, want true")
	}
	if got == nil || got.Organization != "Cloudflare" {
		t.Fatalf("Get() result = %#v, want Organization=Cloudflare", got)
	}
	if queriedAt.IsZero() {
		t.Fatalf("Get() queriedAt is zero, want non-zero")
	}
}

func TestCacheTTLBoundary(t *testing.T) {
	t.Parallel()

	cachePath := filepath.Join(t.TempDir(), "cache.json")
	c, err := New(cachePath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	queriedAt := time.Now().Add(-25 * time.Hour)
	c.entries["8.8.4.4"] = Entry{
		QueriedAt: queriedAt,
		ExpiresAt: queriedAt.Add(cacheTTL),
		Data:      &shodan.ShodanHostResult{IP: "8.8.4.4"},
	}

	got, queriedAt, ok := c.Get("8.8.4.4")
	if ok || got != nil || !queriedAt.IsZero() {
		t.Fatalf("Get() = (%#v, %v, %v), want (nil, zero, false)", got, queriedAt, ok)
	}
}

func TestCacheEvictsOldestAfter100Entries(t *testing.T) {
	t.Parallel()

	cachePath := filepath.Join(t.TempDir(), "cache.json")
	c, err := New(cachePath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	base := time.Now().Add(-2 * time.Hour)
	for i := 0; i < 100; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i%255)
		q := base.Add(time.Duration(i) * time.Millisecond)
		c.entries[ip] = Entry{
			QueriedAt: q,
			ExpiresAt: q.Add(cacheTTL),
			Data:      &shodan.ShodanHostResult{IP: ip},
		}
	}

	c.Set("203.0.113.100", &shodan.ShodanHostResult{IP: "203.0.113.100"})

	if len(c.entries) != maxEntries {
		t.Fatalf("entry count = %d, want %d", len(c.entries), maxEntries)
	}

	if _, ok := c.entries["203.0.113.0"]; ok {
		t.Fatalf("oldest entry was not evicted")
	}
}

func TestCacheAtomicWriteLeavesNoTempFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cachePath := filepath.Join(dir, "cache.json")
	c, err := New(cachePath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	c.Set("8.8.8.8", &shodan.ShodanHostResult{IP: "8.8.8.8"})

	matches, err := filepath.Glob(filepath.Join(dir, ".shodan_cache_*.tmp"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("found leftover temp files: %v", matches)
	}
}

func TestCacheCorruptFileRecovery(t *testing.T) {
	t.Parallel()

	cachePath := filepath.Join(t.TempDir(), "cache.json")
	if err := os.WriteFile(cachePath, []byte("{invalid json"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	c, err := New(cachePath)
	if err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}

	if len(c.entries) != 0 {
		t.Fatalf("entries length = %d, want 0", len(c.entries))
	}
}

func TestCacheVersionMismatchDiscardsEntries(t *testing.T) {
	t.Parallel()

	cachePath := filepath.Join(t.TempDir(), "cache.json")
	payload := `{"version":999,"entries":{"8.8.8.8":{"queried_at":"2026-02-19T00:00:00Z","expires_at":"2026-02-20T00:00:00Z","data":{"IP":"8.8.8.8"}}}}`
	if err := os.WriteFile(cachePath, []byte(payload), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	c, err := New(cachePath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if len(c.entries) != 0 {
		t.Fatalf("entries length = %d, want 0 after version mismatch", len(c.entries))
	}
}

func TestCacheLoadPrunesExpiredEntries(t *testing.T) {
	t.Parallel()

	cachePath := filepath.Join(t.TempDir(), "cache.json")
	now := time.Now()
	payload := fmt.Sprintf(`{"version":1,"entries":{"1.1.1.1":{"queried_at":%q,"expires_at":%q,"data":{"IP":"1.1.1.1"}},"8.8.8.8":{"queried_at":%q,"expires_at":%q,"data":{"IP":"8.8.8.8"}}}}`,
		now.Add(-2*time.Hour).Format(time.RFC3339Nano),
		now.Add(-1*time.Hour).Format(time.RFC3339Nano),
		now.Add(-30*time.Minute).Format(time.RFC3339Nano),
		now.Add(2*time.Hour).Format(time.RFC3339Nano),
	)
	if err := os.WriteFile(cachePath, []byte(payload), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	c, err := New(cachePath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, ok := c.entries["1.1.1.1"]; ok {
		t.Fatalf("expired entry should be pruned")
	}
	if _, ok := c.entries["8.8.8.8"]; !ok {
		t.Fatalf("fresh entry should remain")
	}
}
