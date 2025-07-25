package logger

import (
	"log/slog"
	"os"
	"strings"
)

const log_level_env = "LOG_LEVEL"

func GetLogLevelFromEnv() slog.Level {
	levelStr := strings.ToLower(os.Getenv(log_level_env))
	switch levelStr {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
