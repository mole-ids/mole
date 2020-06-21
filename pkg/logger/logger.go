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
	"strings"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// Log is the global logger for Mole
var Log *zap.SugaredLogger

// Mole is the logger for matches
var Mole *zap.SugaredLogger

// New returns a new logger based on the configuration provided
func New() (err error) {
	var config *Config

	config, err = InitConfig()

	if err != nil {
		return errors.Wrap(err, LoggerConfigInitFailedMsg)
	}

	err = initAppLogger(config)
	if err != nil {
		return errors.Wrap(err, AppLoggerInitFailedMsg)
	}

	err = initMoleLogger(config)
	if err != nil {
		return errors.Wrap(err, MoleLoggerInitFailedMsg)
	}

	return nil
}

func initAppLogger(config *Config) error {
	logConfig := zap.NewProductionConfig()

	// TODO: Add this options at the configuration level
	logConfig.DisableCaller = true
	logConfig.DisableStacktrace = true
	logConfig.Development = false

	// INPROVE: Add the posibility to add extra outputs, like stdout and syslog
	// and even omit stdout
	if !strings.Contains(config.LogTo, "stdout") {
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

	l, err := logConfig.Build()
	if err != nil {
		return ErrBuildingZapFieldsFailed
	}

	Log = l.Sugar()
	defer Log.Sync()

	return nil
}

func initMoleLogger(config *Config) error {
	logConfig := zap.NewProductionConfig()

	// TODO: Add this options at the configuration level
	logConfig.DisableCaller = true
	logConfig.DisableStacktrace = true
	logConfig.Development = false

	logConfig.OutputPaths = []string{config.MoleLogger.To}

	lr, err := logConfig.Build()
	if err != nil {
		return ErrBuildingZapFieldsFailed
	}

	Mole = lr.Sugar()
	defer Mole.Sync()

	return nil
}
