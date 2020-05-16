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

// Execute debug command entry point
func Execute() {
	if err := debugCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func init() {
	// Debug command flags configuration
	cobra.OnInitialize(initConfig)
	debugCmd.PersistentFlags().BoolP("verbose", "v", false, "Make output more verbose")
	debugCmd.PersistentFlags().StringVar(&configFile, "config", "mole.yml", "Config file")
	viper.BindPFlags(debugCmd.Flags())
}

func initConfig() {
	// Define default configuration file
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
