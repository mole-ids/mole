package engine

type Config struct {
}

// InitConfig initializes engine package
func InitConfig() (*Config, error) {
	config := &Config{}

	return config, nil
}
