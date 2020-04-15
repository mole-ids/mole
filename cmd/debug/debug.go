package debug

import (
	"log"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var configFile string

var debugCmd = &cobra.Command{
	Use:   "",
	Short: "debug mode",
}

func Execute() {
	if err := debugCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	debugCmd.PersistentFlags().BoolP("verbose", "v", false, "Make output more verbose")
	debugCmd.PersistentFlags().StringVar(&configFile, "config", "mole.yml", "Config file")
	viper.BindPFlags(debugCmd.Flags())
}

func initConfig() {
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		viper.SetConfigType("yaml")
		viper.SetConfigName("mole")
		viper.AddConfigPath(".")
		viper.AddConfigPath("/etc/mole")
	}

	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err != nil {
		log.Printf("unable to read. %s", err.Error())
	}
}
