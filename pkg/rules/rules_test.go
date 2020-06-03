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
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

func writeIndex(dir, iname, rname string) {
	var err error
	err = os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		fmt.Println("Error creating test directory:", err.Error())
	}
	i := fmt.Sprintf("include \"%s\"", rname)
	ioutil.WriteFile(filepath.Join(dir, iname), []byte(i), 0655)

	fmt.Printf("Writing index %s with content: \n%s\n", filepath.Join(dir, iname), i)
}

func writeRules(dir, name, content string) {
	var err error
	err = os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		fmt.Println("Error creating test directory:", err.Error())
	}
	ioutil.WriteFile(filepath.Join(dir, name), []byte(content), 0655)

	fmt.Printf("Writing rule file %s with content:\n%s\n", filepath.Join(dir, name), content)
}

func TestNewManager(t *testing.T) {
	var err error

	startup()
	initViper(test_config, filepath.Join(test_dir, test_rulesDir))

	_, err = NewManager()
	if err != nil {
		t.Errorf("Expected no error but found: %s", err.Error())
	}

}

func TestLoadRulesByDir(t *testing.T) {
	testCase := []struct {
		cfg      string
		rFolder  string
		rfErr    bool
		rIndex   string
		riErr    bool
		rName    string
		rule     string
		rawRules int
		err      bool
	}{{
		cfg: `
rules:
  rules_dir: %s
  variables:
    $TCP: tcp
    $HOME_NET: "10.0.0.0/8"
`,
		rFolder:  "",
		rfErr:    true,
		rIndex:   "",
		riErr:    true,
		rName:    "",
		rule:     "",
		rawRules: 0,
		err:      true,
	}, {
		cfg: `
rules:
  rules_dir: %s
  variables:
    $TCP: tcp
    $HOME_NET: "10.0.0.0/8"
`,
		rFolder:  test_rulesDir,
		rfErr:    false,
		rIndex:   test_rulesIndex,
		riErr:    false,
		rName:    test_rulesName,
		rule:     `rule R { condition: $ }`,
		rawRules: 1,
		err:      false,
	}}

	startup()
	viper.Reset()

	for idx, tc := range testCase {
		if idx != 0 {
			initViper(fmt.Sprintf(tc.cfg, tc.rFolder), test_dir)
		}
		if len(tc.rule) > 0 {
			writeRules(filepath.Join(test_dir, tc.rFolder), tc.rName, tc.rule)
		}

		ma, err := NewManager()

		if tc.err && err == nil {
			t.Errorf("[%d] Expecting error but none found", idx)
		}

		if !tc.err && err != nil {
			t.Errorf("[%d] Expecting no error but found: %s", idx, err.Error())
		}

		if !tc.err {
			if ma.Config.RulesFolder != filepath.Join(test_dir, tc.rFolder) {
				t.Errorf("[%d] Expecting RulesFolder to be %s, but found %s", idx, filepath.Join(test_dir, tc.rFolder), ma.Config.RulesFolder)
			}

			if ma.Config.RulesIndex != "" {
				t.Errorf("[%d] Expecting RulesIndex to be '', but found %s", idx, ma.Config.RulesIndex)
			}

			if len(ma.RawRules) != tc.rawRules {
				t.Errorf("[%d] Expecting to have %d RawRules, but found %d", idx, tc.rawRules, len(ma.RawRules))
			}
		}
		shutdown()
	}
}

func TestLoadRulesByIndex(t *testing.T) {
	testCase := []struct {
		cfg            string
		rFolder        string
		rIndex         string
		rName          string
		rule           string
		rawRules       int
		checkIndex     bool
		err            bool
		errLoadingFile bool
	}{{
		cfg: `
rules:
  rules_index: %s/index.yar
  variables:
    $TCP: tcp
    $HOME_NET: "10.0.0.0/8"
`,
		rFolder:        ".",
		rIndex:         "",
		rName:          "",
		rule:           "",
		rawRules:       0,
		checkIndex:     true,
		err:            true,
		errLoadingFile: false,
	}, {
		cfg: `
rules:
  rules_index: %s/index.yar
  variables:
    $TCP: tcp
    $HOME_NET: "10.0.0.0/8"
`,
		rFolder:        ".",
		rIndex:         test_rulesIndex,
		rName:          test_rulesName,
		rule:           `rule R { condition: $ }`,
		rawRules:       1,
		checkIndex:     true,
		err:            false,
		errLoadingFile: false,
	}, {
		cfg: `
rules:
  rules_index: %s/index.yar
  variables:
    $TCP: tcp
    $HOME_NET: "10.0.0.0/8"
`,
		rFolder:        ".",
		rIndex:         test_rulesIndex,
		rName:          test_rulesName,
		rule:           `rule R { condition: $ } rule R1 { condition: $ }`,
		rawRules:       2,
		checkIndex:     true,
		err:            false,
		errLoadingFile: false,
	}, {
		cfg: `
rules:
  rules_index: %s/index.yar1
  variables:
    $TCP: tcp
    $HOME_NET: "10.0.0.0/8"
`,
		rFolder:        ".",
		rIndex:         "index.ERROR",
		rName:          test_rulesName,
		rule:           `rule R { condition: $ }`,
		rawRules:       0,
		checkIndex:     false,
		err:            false,
		errLoadingFile: true,
	}}

	startup()
	viper.Reset()

	for idx, tc := range testCase {
		if idx != 0 {
			initViper(fmt.Sprintf(tc.cfg, tc.rFolder), filepath.Join(test_dir, tc.rFolder))
		}
		writeIndex(test_dir, tc.rIndex, tc.rName)
		writeRules(test_dir, tc.rName, tc.rule)

		ma, err := NewManager()

		if tc.err && err == nil {
			t.Errorf("[%d] Expecting error but none found", idx)
		}

		if !tc.err && err != nil {
			t.Errorf("[%d] Expecting no error but found: %s", idx, err.Error())
		}

		if !tc.err {
			if ma.Config.RulesFolder != "" {
				t.Errorf("[%d] Expecting RulesFolder to be '', but found %s", idx, ma.Config.RulesFolder)
			}

			if tc.checkIndex && filepath.Base(ma.Config.RulesIndex) != tc.rIndex {
				t.Errorf("[%d] Expecting RulesIndex to be %s, but found %s", idx, tc.rIndex, filepath.Base(ma.Config.RulesIndex))
			}

			if len(ma.RawRules) != tc.rawRules {
				t.Errorf("[%d] Expecting to have %d RawRules, but found %d", idx, tc.rawRules, len(ma.RawRules))
			}
		}
		shutdown()
	}
}

func TestLoadRulesWithConfig(t *testing.T) {
	var err error

	testCase := []struct {
		cfg string
		err bool
	}{{
		cfg: `
rules:
  rules_dir: ./rules
  rules_index: index.yar
  variables:
    $TCP: tcp
    $HOME_NET: "10.0.0.0/8"
`,
		err: false,
	}, {
		cfg: `
rules:
  variables:
    $TCP: tcp
    $HOME_NET: "10.0.0.0/8"
`,
		err: true,
	}}

	startup()
	for idx, tc := range testCase {
		initViper(tc.cfg, filepath.Join(test_dir, test_rulesDir))

		_, err = NewManager()
		if tc.err && err == nil {
			t.Errorf("[%d] Expecting error but none found", idx)
		}

		if !tc.err && err != nil {
			t.Errorf("[%d] Unexpected error: %s", idx, err.Error())
		}
	}
	shutdown()
}
