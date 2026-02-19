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
	cachePath := filepath.Join(t.TempDir(), "cache.json")
	c, err := New(cachePath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	for i := 0; i < 101; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i%255)
		c.Set(ip, &shodan.ShodanHostResult{IP: ip})
		time.Sleep(1 * time.Millisecond)
	}

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
