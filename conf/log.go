package conf

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LoggingConfig specifies all the parameters needed for logging
type LoggingConfig struct {
	Level string `mapstructure:"level"`
	File  string `mapstructure:"file"`
}

// ConfigureLogging will take the logging configuration and also adds
// a few default parameters
func ConfigureLogging(config *LoggingConfig) (logger *zap.SugaredLogger, err error) {
	hostname, err := os.Hostname()
	if err != nil {
		return
	}

	logConfig := zap.NewProductionConfig()
	logConfig.DisableCaller = true
	logConfig.Development = false

	// use a file if you want
	if config.File != "" {
		logConfig.OutputPaths = append(logConfig.OutputPaths, config.File)
	}

	switch config.Level {
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
	logger = l.Sugar()
	return
}
