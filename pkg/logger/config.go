package logger

import "github.com/spf13/viper"

type Config struct {
	LogTo    string
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
