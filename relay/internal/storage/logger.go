package storage

import (
	"fmt"
	"log/slog"
	"strings"
)

type logger struct {
	lvl slog.Level
}

func newLogger(lvl slog.Level) logger {
	return logger{lvl: lvl}
}

func (l logger) Errorf(s string, i ...interface{}) {
	if l.lvl > slog.LevelError {
		return
	}
	slog.Error("storage", slog.String("badger", message(s, i)))
}

func (l logger) Warningf(s string, i ...interface{}) {
	if l.lvl > slog.LevelWarn {
		return
	}
	slog.Warn("storage", slog.String("badger", message(s, i)))
}

func (l logger) Infof(s string, i ...interface{}) {
	if l.lvl > slog.LevelInfo {
		return
	}
	slog.Info("storage", slog.String("badger", message(s, i)))
}

func (l logger) Debugf(s string, i ...interface{}) {
	if l.lvl > slog.LevelDebug {
		return
	}
	slog.Debug("storage", slog.String("badger", message(s, i)))
}

func message(s string, i []interface{}) string {
	return strings.TrimSuffix(fmt.Sprintf(s, i...), "\n")
}
