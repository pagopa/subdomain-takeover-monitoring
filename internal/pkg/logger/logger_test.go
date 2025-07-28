package logger

import (
	"log/slog"
	"os"
	"testing"
)

func TestGetLogLevelFromEnv(t *testing.T) {
	tests := []struct {
		envValue  string
		wantLevel slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"INFO", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"WARN", slog.LevelWarn},
		{"error", slog.LevelError},
		{"ERROR", slog.LevelError},
		{"invalid", slog.LevelInfo}, // default fallback
		{"", slog.LevelInfo},        // unset = default
	}

	for _, tt := range tests {
		t.Run(tt.envValue, func(t *testing.T) {
			// Set the environment variable
			os.Setenv(LOG_LEVEL_ENV, tt.envValue)
			defer os.Unsetenv(LOG_LEVEL_ENV) // cleanup

			got, _ := GetLogLevelFromEnv()
			if got != tt.wantLevel {
				t.Errorf("GetLogLevelFromEnv() with LOG_LEVEL=%q = %v, want %v",
					tt.envValue, got, tt.wantLevel)
			}
		})
	}
}
