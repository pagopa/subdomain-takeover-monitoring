package logger

import (
	"log/slog"
	"os"
)

const LOG_LEVEL_ENV = "LOG_LEVEL"

func GetLogLevelFromEnv() (slog.Level, error) {
	var level slog.Level
	err := level.UnmarshalText([]byte(os.Getenv(LOG_LEVEL_ENV)))
	if err != nil {
		slog.Error(err.Error())
		return 0, err
	}
	return level, nil
}

func SetLogger() {
	lvl := new(slog.LevelVar)
	level, err := GetLogLevelFromEnv()
	if err != nil {
		return
	}
	lvl.Set(level)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(logger)
}
