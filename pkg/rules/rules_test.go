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
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/mole-ids/mole/pkg/logger"
	"github.com/spf13/viper"
)

var (
	dir, _ = ioutil.TempDir("", "")
)

const (
	config1 = `
rules:
  rules_index: %s
  variables:
    $TCP:
      - tcp
    $HOME_NET:
      - "10.0.0.0/8"`
)

func init() {
	logger.New()
}

func writeIndex() {
	i := `include "./rule.yar"`
	ioutil.WriteFile(filepath.Join(dir, "index.yar"), []byte(i), 0655)
}

func writeRules() {
	r := `rule ExampleRule {
meta:
	type = "alert"
	proto = "tcp"
	src = "192.168.0.1"
	src_port = "any"
	dst = "any"
    dst_port = "80"
strings:
	$my_text_string = "google.com"
	$my_hex_string = { 8d }
	$my_hex_string2 = { 00 }

condition:
	$my_text_string or $my_hex_string or $my_hex_string2
}
	`
	ioutil.WriteFile(filepath.Join(dir, "rule.yar"), []byte(r), 0655)
}

func TestNewManagerCustom(t *testing.T) {
	var err error

	_, err = NewManagerCustom()
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}

}

func TestLoadRulesByDir(t *testing.T) {
	var err error

	viper.Reset()

	writeRules()

	ma, err := NewManagerCustom()
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}

	if ma.Config.RulesFolder != "" {
		t.Errorf("Expecting configuration RulesFolder to be empty, but found %s", ma.Config.RulesFolder)
	}

	if ma.Config.RulesIndex != "" {
		t.Errorf("Expecting configuration RulesIndex to be empty, but found %s", ma.Config.RulesIndex)
	}

	if len(ma.RawRules) != 0 {
		t.Errorf("Expecting no RawRules, but found %d", len(ma.RawRules))
	}

	ma.LoadRulesByDir(dir)

	if len(ma.RawRules) != 1 {
		t.Errorf("Expecting to have 1 RawRules, but found %d", len(ma.RawRules))
	}
}

func TestLoadRulesByIndex(t *testing.T) {
	var err error

	viper.Reset()

	writeIndex()
	writeRules()

	ma, err := NewManagerCustom()
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}

	if ma.Config.RulesFolder != "" {
		t.Errorf("Expecting configuration RulesFolder to be empty, but found %s", ma.Config.RulesFolder)
	}

	if ma.Config.RulesIndex != "" {
		t.Errorf("Expecting configuration RulesIndex to be empty, but found %s", ma.Config.RulesIndex)
	}

	if len(ma.RawRules) != 0 {
		t.Errorf("Expecting no RawRules, but found %d", len(ma.RawRules))
	}

	ma.LoadRulesByIndex(filepath.Join(dir, "index.yar"))

	if len(ma.RawRules) != 1 {
		t.Errorf("Expecting to have 1 RawRules, but found %d", len(ma.RawRules))
	}
}

func TestLoadRulesWithoutConfig(t *testing.T) {
	var err error

	viper.Reset()

	_, err = NewManager()
	if err == nil {
		t.Error("Expected error but none found")
	}
}

func TestLoadRulesWithConfig(t *testing.T) {
	var err error

	viper.Reset()

	name := "mole"
	ext := "yml"
	fname := name + "." + ext
	fpath := filepath.Join(dir, fname)

	ioutil.WriteFile(fpath, []byte(fmt.Sprintf(config1, filepath.Join(dir, "index.yar"))), 0655)

	viper.Reset()
	viper.SetConfigType("yaml")
	viper.SetConfigName(name)
	viper.AddConfigPath(dir)

	err = viper.ReadInConfig()
	if err != nil {
		t.Errorf("Fatal error config file: %s", err)
	}

	_, err = NewManager()
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}

}
