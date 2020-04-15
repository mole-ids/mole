package logger

import (
	"os"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	Config *Config
	Log    *zap.SugaredLogger
}

func New() (log *Logger, err error) {
	log = &Logger{}
	log.Config, err = InitConfig()

	if err != nil {
		return nil, errors.Wrap(err, "unable to initiate logger configutation")
	}

	var hostname string
	hostname, err = os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	logConfig := zap.NewProductionConfig()
	logConfig.DisableCaller = true
	logConfig.Development = false

	logConfig.OutputPaths = append(logConfig.OutputPaths, log.Config.LogTo)

	switch log.Config.LogLevel {
	case "debug":
		logConfig.Level.SetLevel(zap.DebugLevel)
	case "warning":
		logConfig.Level.SetLevel(zap.WarnLevel)
	case "error":
		logConfig.Level.SetLevel(zap.ErrorLevel)
	case "info":
		fallthrough
	default:
		logConfig.Level.SetLevel(zap.InfoLevel)
	}

	op := zap.Field{
		Key:    "hostname",
		Type:   zapcore.StringType,
		String: hostname,
	}
	l, err := logConfig.Build(zap.Fields(op))
	if err != nil {
		return nil, errors.Wrap(err, "unable to build logger fields")
	}
	log.Log = l.Sugar()

	return log, nil
}
