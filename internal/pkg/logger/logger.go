package logger

import (
	"log/slog"
	"os"
)

func SetupLogger(level slog.Leveler) {

	opts := &slog.HandlerOptions{
		Level: level,
	}

	handler := slog.NewJSONHandler(os.Stderr, opts)
	logger := slog.New(handler)
	slog.SetDefault(logger)
}
