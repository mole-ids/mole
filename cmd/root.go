package cmd

import (
	"log"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var RootCmd = &cobra.Command{
	Use:   "mole",
	Short: "MOLE IDS",
}

var configFile string

// Execute command entrypoint
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	RootCmd.PersistentFlags().BoolP("verbose", "v", false, "Make output more verbose")
	RootCmd.PersistentFlags().StringVar(&configFile, "config", "mole.yml", "Config file")
	viper.BindPFlags(RootCmd.Flags())
}

func initConfig() {
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
