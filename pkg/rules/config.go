package rules

import (
	"github.com/spf13/viper"
)

// Config rules internal configuration
type Config struct {
	RulesIndex  string
	RulesFolder string
	Vars        map[string][]string
}

// InitConfig initializes rules package
func InitConfig() (*Config, error) {
	config := &Config{
		RulesIndex:  viper.GetString("rules.rules_index"),
		RulesFolder: viper.GetString("rules.rules_dir"),
		Vars:        viper.GetStringMapStringSlice("rules.variables"),
	}

	// Mole overwritten variables
	config.Vars["$tcp"] = []string{"TCP"}
	config.Vars["$udp"] = []string{"UDP"}
	config.Vars["$any_addr"] = []string{"0.0.0.0/0"}
	config.Vars["$any_port"] = []string{"0:65535"}

	return config, nil
}
