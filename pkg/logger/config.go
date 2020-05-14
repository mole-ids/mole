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
