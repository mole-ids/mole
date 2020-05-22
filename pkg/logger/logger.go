// Copyright 2020 Jaume Martin

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package logger

import (
	"os"

	"github.com/mole-ids/mole/internal/merr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Log is the global logger for Mole
var Log *zap.SugaredLogger

// Result is the logger for matches
var Result *zap.SugaredLogger

// New returns a new logger based on the configuration provided
func New() (err error) {
	var config *Config

	config, err = InitConfig()

	if err != nil {
		return merr.ErrLoggerInitConfig
	}

	var hostname string
	hostname, err = os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	logConfig := zap.NewProductionConfig()

	// TODO: Add this options at the configuration level
	logConfig.DisableCaller = true
	logConfig.DisableStacktrace = true
	logConfig.Development = false

	// INPROVE: Add the posibility to add extra outputs, like stdout and syslog
	// and even omit stdout
	if config.LogTo != "/dev/stdout" {
		logConfig.OutputPaths = append(logConfig.OutputPaths, config.LogTo)
	}

	switch config.LogLevel {
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
		return merr.ErrLoggerBuildZapFields
	}

	Log = l.Sugar()
	defer Log.Sync()

	// TODO: This needs to be done properly. Maybe using its own configuration
	// variables
	lr, err := logConfig.Build(zap.Fields(op))
	if err != nil {
		return merr.ErrLoggerBuildZapFields
	}

	Result = lr.Sugar()
	defer Result.Sync()

	Log.Infof(LoggerInitSuccessMsg, logConfig.Level.Level().CapitalString())

	return nil
}
