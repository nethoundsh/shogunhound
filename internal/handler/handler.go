package handler

import (
	"log/slog"
	"os"

	"github.com/nethoundsh/shogunhound/internal/cache"
	"github.com/nethoundsh/shogunhound/internal/shodan"
)

type ToolHandler struct {
	cache   *cache.Cache
	shodan  *shodan.ShodanClient
	logger  *slog.Logger
	logFile *os.File
}

func New(cache *cache.Cache, client *shodan.ShodanClient, logPath string) (*ToolHandler, error) {
	resolvedLogPath, err := resolvePath(logPath)
	if err != nil {
		return nil, err
	}

	logFile, err := os.OpenFile(resolvedLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}

	return &ToolHandler{
		cache:   cache,
		shodan:  client,
		logger:  slog.New(slog.NewJSONHandler(logFile, nil)),
		logFile: logFile,
	}, nil
}

func (h *ToolHandler) Close() error {
	if h == nil || h.logFile == nil {
		return nil
	}
	return h.logFile.Close()
}
