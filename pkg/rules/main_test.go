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
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/mole-ids/mole/pkg/logger"
	"github.com/spf13/viper"
)

var (
	test_dir string
)

func TestMain(m *testing.M) {
	startup()
	code := m.Run()
	shutdown()
	os.Exit(code)
}

func startup() {
	var err error
	logger.New()

	test_dir, err = ioutil.TempDir("", "")
	if err != nil {
		log.Fatal(err)
	}

}

func shutdown() {
	os.RemoveAll(test_dir)
}

const (
	test_rulesDir   = "./rules"
	test_rulesIndex = "index.yar"
	test_rulesName  = "rule.yar"

	test_cstyle   = "C-Style comment"
	test_cppstyle = "Cpp-Style comment"

	test_rule = `
/* C-Style comment */
rule ExampleRuleC
{
	/*
	C-Style comment -- strings
	*/
	strings:
		$my_text_string = "google.com" // Cpp-Style comment
		$my_hex_string = { 8d }
		$my_hex_string2 = { 00 }
	// Cpp-Style comment -- strings
	condition:
		$my_text_string or $my_hex_string or $my_hex_string2
}
// Cpp-Style comment
`
	test_config = `
rules:
  rules_dir: rules
  rules_index: rules/index.yar
  variables:
    $TCP: tcp
    $HOME_NET: "10.0.0.0/8"
`
	test_config_index = `
rules:
  rules_index: %s/index.yar
  variables:
    $TCP: tcp
    $HOME_NET: "10.0.0.0/8"
`

	test_config_dir = `
rules:
  rules_dir: %s/rules
  variables:
    $TCP: tcp
    $HOME_NET: "10.0.0.0/8"
`
)

func initViper(cfg string) {
	name := "mole"
	ext := "yml"

	fileName := name + "." + ext
	filePath := filepath.Join(test_dir, fileName)

	err := ioutil.WriteFile(filePath, []byte(cfg), 0655)
	if err != nil {
		fmt.Println("Error crating mole.yml")
		fmt.Println("Err: ", err.Error())
	}

	viper.Reset()
	viper.SetConfigType("yaml")
	viper.SetConfigName(name)
	viper.AddConfigPath(test_dir)

	err = viper.ReadInConfig()
	if err != nil {
		fmt.Printf("Fatal error config file: %s", err.Error())
	}
}

func buildConfig(rpath, rindex string, vars map[string]string) string {
	var variables string
	tpl := `
rules:
  rules_dir: %s
  rules_index: %s
  variables:
%s
`
	for k, v := range vars {
		variables += "    " + k + ": " + v + "\n"
	}

	return fmt.Sprintf(tpl, rpath, rindex, variables)
}

func writeIndex(indexFileName, ruleFileName string) {
	if indexFileName == "" {
		return
	}

	var err error
	path := filepath.Join(test_dir, indexFileName)
	base := filepath.Dir(path)

	err = os.MkdirAll(base, os.ModePerm)
	if err != nil {
		logger.Log.Errorf("Error while creating the path for index file: %s", err.Error())
	}

	i := fmt.Sprintf("include \"%s\"", ruleFileName)
	err = ioutil.WriteFile(path, []byte(i), os.ModePerm)
	if err != nil {
		logger.Log.Errorf("Error while writing test index: %s", err.Error())
	}
}

func writeRule(ruleFileName, ruleContent string) {
	if ruleFileName == "" {
		return
	}

	var err error
	path := filepath.Join(test_dir, ruleFileName)
	base := filepath.Dir(path)

	err = os.MkdirAll(base, os.ModePerm)
	if err != nil {
		logger.Log.Errorf("Error while creating the path folders: %s", err.Error())
	}

	err = ioutil.WriteFile(path, []byte(ruleContent), os.ModePerm)
	if err != nil {
		logger.Log.Errorf("Error while writing test rules: %s", err.Error())
	}
}
