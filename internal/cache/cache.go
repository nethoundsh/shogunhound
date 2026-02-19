package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nethoundsh/shogunhound/internal/shodan"
)

const (
	cacheTTL   = 24 * time.Hour
	maxEntries = 100
	// cacheVersion is written to disk for future compatibility checks.
	// It is not currently validated on load.
	cacheVersion = 1
)

type Entry struct {
	QueriedAt time.Time                `json:"queried_at"`
	ExpiresAt time.Time                `json:"expires_at"`
	Data      *shodan.ShodanHostResult `json:"data"`
}

type cacheFile struct {
	Version int              `json:"version"`
	Entries map[string]Entry `json:"entries"`
}

type Cache struct {
	path    string
	mu      sync.RWMutex
	entries map[string]Entry
}

func New(path string) (*Cache, error) {
	resolvedPath, err := expandPath(path)
	if err != nil {
		return nil, err
	}

	c := &Cache{
		path:    resolvedPath,
		entries: make(map[string]Entry),
	}

	if err := c.load(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return c, nil
		}

		fmt.Fprintf(os.Stderr, "warning: failed to load cache file %s: %v; starting with empty cache\n", c.path, err)
		c.entries = make(map[string]Entry)
	}

	return c, nil
}

func (c *Cache) Get(ip string) (*shodan.ShodanHostResult, time.Time, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[ip]
	if !ok {
		return nil, time.Time{}, false
	}

	if !time.Now().Before(entry.ExpiresAt) {
		return nil, time.Time{}, false
	}

	return entry.Data, entry.QueriedAt, true
}

func (c *Cache) Set(ip string, result *shodan.ShodanHostResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	c.entries[ip] = Entry{
		QueriedAt: now,
		ExpiresAt: now.Add(cacheTTL),
		Data:      result,
	}

	if len(c.entries) > maxEntries {
		var (
			oldestIP string
			oldestAt time.Time
			first    = true
		)

		for key, entry := range c.entries {
			if first || entry.QueriedAt.Before(oldestAt) {
				oldestIP = key
				oldestAt = entry.QueriedAt
				first = false
			}
		}

		delete(c.entries, oldestIP)
	}

	if err := c.save(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to save cache file %s: %v\n", c.path, err)
	}
}

func (c *Cache) Evict(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, ip)
	if err := c.save(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to save cache file %s: %v\n", c.path, err)
	}
}

func (c *Cache) save() error {
	payload, err := json.Marshal(cacheFile{
		Version: cacheVersion,
		Entries: c.entries,
	})
	if err != nil {
		return err
	}

	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".shodan_cache_*.tmp")
	if err != nil {
		return err
	}

	tmpName := tmp.Name()
	cleanup := func() {
		_ = os.Remove(tmpName)
	}

	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}

	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}

	if err := os.Rename(tmpName, c.path); err != nil {
		cleanup()
		return err
	}

	return nil
}

func (c *Cache) load() error {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return err
	}

	var payload cacheFile
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	if payload.Entries == nil {
		c.entries = make(map[string]Entry)
		return nil
	}

	c.entries = payload.Entries
	return nil
}

func expandPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("cache path cannot be empty")
	}

	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}

		if path == "~" {
			return home, nil
		}

		if strings.HasPrefix(path, "~/") {
			return filepath.Join(home, path[2:]), nil
		}
	}

	return path, nil
}
