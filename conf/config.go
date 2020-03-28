package conf

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Config represents a Mole configuration
type Config struct {
	IFace      string         `mapstructure:"iface"`
	RulesDir   string         `mapstructure:"rules_dir"`
	RulesIndex string         `mapstructure:"rules_index"`
	BPFfilter  string         `mapstructure:"bpf_filter"`
	LogConfig  *LoggingConfig `mapstructure:"log_conf"`
}

// LoadConfig loads the configuration based on a command
func LoadConfig(cmd *cobra.Command) (cfg *Config, err error) {
	configFile, err := cmd.Flags().GetString("config")
	if err != nil {
		return
	}
	if configFile != "" {
		viper.SetConfigFile(configFile)
		viper.Unmarshal(&cfg)
		return
	}
	// from the command itself
	if err = viper.BindPFlags(cmd.Flags()); err != nil {
		return
	}

	// from the environment
	viper.SetEnvPrefix("MOLE")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// from a config file
	viper.SetConfigName("mole")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/etc/mole/")
	viper.AddConfigPath(".")

	// NOTE: this will require that you have config file somewhere in the paths specified. It can be reading from JSON, TOML, YAML, HCL, and Java properties files.
	if err = viper.ReadInConfig(); err != nil {
		return
	}

	err = viper.Unmarshal(&cfg)
	if err != nil {
		return
	}
	return
}
