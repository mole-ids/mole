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
package rules

import (
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

// Config rules internal configuration
type Config struct {
	// RulesIndex path to a Yara rule index
	RulesIndex string
	// RulesFolder path to a directory with a set of Yara rules
	RulesFolder string
	// Vars vaiables used for overwriting values in the Yara rules meta section
	Vars map[string]string
}

// InitConfig initializes rules package
func InitConfig() (*Config, error) {
	var err error
	config := &Config{
		RulesIndex:  viper.GetString("rules.rules_index"),
		RulesFolder: viper.GetString("rules.rules_dir"),
		Vars:        viper.GetStringMapString("rules.variables"),
	}

	cfgFile := viper.ConfigFileUsed()

	if cfgFile != "" {
		// Options come from config file
		base := filepath.Dir(cfgFile)
		if config.RulesFolder != "" {
			config.RulesFolder = filepath.Join(base, config.RulesFolder)
		}
		if config.RulesIndex != "" {
			config.RulesIndex = filepath.Join(base, config.RulesIndex)
		}

	} else {
		// Otherwise, we need values to be absolute path
		if config.RulesFolder != "" && !filepath.IsAbs(config.RulesFolder) {
			err = ErrRuleFolderPathIsNotAbs
		}
		if config.RulesIndex != "" && !filepath.IsAbs(config.RulesIndex) {
			if err != nil {
				err = errors.Wrap(err, IndexFilePathIsNotAbsEitherMsg)
			} else {
				err = ErrIndexFilePathIsNotAbs
			}
		}
	}

	if config.RulesFolder == "" && config.RulesIndex == "" {
		err = ErrIndexOrRuleFolderPathRequired
	}

	// Mole overwritten variables
	config.Vars["$tcp"] = "tcp"
	config.Vars["$udp"] = "udp"
	config.Vars["$sctp"] = "sctp"
	config.Vars["$any_addr"] = "0.0.0.0/0"
	config.Vars["$any_port"] = "0:65535"

	return config, err
}
