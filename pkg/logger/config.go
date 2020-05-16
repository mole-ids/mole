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

import "github.com/spf13/viper"

// Config logger internal configuration
type Config struct {
	// LogTo where the logger will write to
	LogTo string
	// LogLevel logger level. This can take info, error, warning, and debug
	LogLevel string
}

// InitConfig initializes logger package
func InitConfig() (*Config, error) {
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

	return config, nil
}
