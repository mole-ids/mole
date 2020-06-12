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
	"github.com/spf13/viper"
)

// Config logger internal configuration
type Config struct {
	// LogTo where the logger will write to
	LogTo string
	// LogLevel logger level. This can take info, error, warning, and debug
	LogLevel string

	MoleLogger MoleLogger
}

type MoleLogger struct {
	To     string
	Format string
}

// InitConfig initializes logger package
func InitConfig() (*Config, error) {
	var err error
	config := &Config{
		LogTo:    viper.GetString("logger.log_to"),
		LogLevel: viper.GetString("logger.log_level"),
	}

	if config.LogTo == "" {
		config.LogTo = "/dev/stdout"
	}

	if config.LogLevel == "" {
		config.LogLevel = "info"
	}

	mole := MoleLogger{
		To:     viper.GetString("logger.mole.to"),
		Format: viper.GetString("logger.mole.format"),
	}

	if mole.To == "" {
		mole.To = "/dev/stdout"
	}

	if mole.Format != "" {
		mole.Format = "eve"
	}

	config.MoleLogger = mole

	return config, err
}
