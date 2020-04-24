package cmd

import (
	"fmt"
	"log"
	"strings"

	"github.com/jpalanco/mole/pkg/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err != nil {
		log.Printf("unable to read. %s", err.Error())
	}
}
