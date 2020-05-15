package cmd

import (
	"fmt"
	"log"
	"strings"

	"github.com/mole-ids/mole/pkg/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	AppName = "Mole IDS"
	Version = "v0.0.0"
	BuildHash = "devel"
	BuildDate = "1970-01-01T00:00:00Z"
)

// RootCmd root command, this is the main entry point command
var RootCmd = &cobra.Command{
	Use:   "",
	Short: "MOLE IDS",
	PreRun: func(cmd *cobra.Command, args []string) {
		err := logger.New()
		if err != nil {
			fmt.Printf("Err: %s\n", err.Error())
		}
	},
}

// configFile configuration file
var configFile string

// Execute command entrypoint
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func init() {
	// Root flags configuration
	cobra.OnInitialize(initConfig)
	RootCmd.PersistentFlags().StringVar(&configFile, "config", "mole.yml", "Config file")

	RootCmd.PersistentFlags().String("logTo", "", "Log to file")
	RootCmd.PersistentFlags().String("logLevel", "info", "Log level")

	RootCmd.PersistentFlags().Bool("version", false, "Show Mole version")
	
	// Bind flags to configuration file
	viper.BindPFlag("logger.log_to", RootCmd.PersistentFlags().Lookup("logTo"))
	viper.BindPFlag("logger.log_level", RootCmd.PersistentFlags().Lookup("logLevel"))

}

func initConfig() {
	// Define default configuration file
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		viper.SetConfigName("mole")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("/etc/mole")
	}

	// Read configuration from environment variables
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err != nil {
		log.Printf("unable to read. %s", err.Error())
	}
}
