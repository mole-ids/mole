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

	"github.com/spf13/viper"
)

func writeIndex(dir, iname, rname string) {
	i := fmt.Sprintf(`include "%s"`, rname)
	ioutil.WriteFile(filepath.Join(dir, iname), []byte(i), 0655)
}

func writeRules(dir, name, content string) {
	ioutil.WriteFile(filepath.Join(dir, name), []byte(content), 0655)
}

func TestNewManager(t *testing.T) {
	var err error

	_, err = NewManager()
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}

}

func TestLoadRulesByDir(t *testing.T) {
	testCase := []struct {
		cfg      string
		rFolder  string
		rIndex   string
		rName    string
		rule     string
		rawRules int
		err      bool
	}{{
		cfg: `
rules:
  rules_dir: %s
  variables:
    $TCP:
      - tcp
    $HOME_NET:
      - "10.0.0.0/8"
`,
		rFolder:  "",
		rIndex:   "",
		rName:    "",
		rule:     "",
		rawRules: 0,
		err:      false,
	}, {
		cfg: `
rules:
  rules_dir: %s
  variables:
    $TCP:
      - tcp
    $HOME_NET:
      - "10.0.0.0/8"
`,
		rFolder:  test_dir,
		rIndex:   test_rulesIndex,
		rName:    test_rulesName,
		rule:     `rule R { condition: $ }`,
		rawRules: 1,
		err:      false,
	}}

	viper.Reset()

	for idx, tc := range testCase {
		if len(tc.rule) > 0 {
			writeRules(tc.rFolder, tc.rName, tc.rule)
		}
		if idx != 0 {
			initViper(fmt.Sprintf(tc.cfg, tc.rFolder))
		}

		ma, err := NewManager()

		if tc.err && err == nil {
			t.Errorf("[%d] Expecting error but none found", idx)
		}

		if !tc.err && err != nil {
			t.Errorf("[%d] Expecting no error but found: %s", idx, err.Error())
		}

		if ma.Config.RulesFolder != tc.rFolder {
			t.Errorf("[%d] Expecting RulesFolder to be %s, but found %s", idx, tc.rFolder, ma.Config.RulesFolder)
		}

		if ma.Config.RulesIndex != "" {
			t.Errorf("[%d] Expecting RulesIndex to be '', but found %s", idx, ma.Config.RulesIndex)
		}

		if len(ma.RawRules) != 0 {
			t.Errorf("[%d] Expecting no RawRules, but found %d", idx, len(ma.RawRules))
		}

		if idx != 0 {
			ma.LoadRulesByDir(tc.rFolder)
		}

		if len(ma.RawRules) != tc.rawRules {
			t.Errorf("[%d] Expecting to have %d RawRules, but found %d", idx, tc.rawRules, len(ma.RawRules))
		}
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
    $TCP:
      - tcp
    $HOME_NET:
      - "10.0.0.0/8"
`,
		rFolder:        "",
		rIndex:         ".",
		rName:          "",
		rule:           "",
		rawRules:       0,
		checkIndex:     true,
		err:            false,
		errLoadingFile: false,
	}, {
		cfg: `
rules:
  rules_index: %s/index.yar
  variables:
    $TCP:
      - tcp
    $HOME_NET:
      - "10.0.0.0/8"
`,
		rFolder:        test_dir,
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
  rules_index: %s/index.yar1
  variables:
    $TCP:
      - tcp
    $HOME_NET:
      - "10.0.0.0/8"
`,
		rFolder:        test_dir,
		rIndex:         "index.ERROR",
		rName:          test_rulesName,
		rule:           `rule R { condition: $ }`,
		rawRules:       0,
		checkIndex:     false,
		err:            false,
		errLoadingFile: true,
	}}

	viper.Reset()

	for idx, tc := range testCase {
		writeIndex(tc.rFolder, tc.rIndex, tc.rName)
		writeRules(tc.rFolder, tc.rName, tc.rule)
		if idx != 0 {
			initViper(fmt.Sprintf(tc.cfg, tc.rFolder))
		}

		ma, err := NewManager()

		if tc.err && err == nil {
			t.Errorf("[%d] Expecting error but none found", idx)
		}

		if !tc.err && err != nil {
			t.Errorf("[%d] Expecting no error but found: %s", idx, err.Error())
		}

		if ma.Config.RulesFolder != "" {
			t.Errorf("[%d] Expecting RulesFolder to be '', but found %s", idx, ma.Config.RulesFolder)
		}

		if tc.checkIndex && filepath.Base(ma.Config.RulesIndex) != tc.rIndex {
			t.Errorf("[%d] Expecting RulesIndex to be %s, but found %s", idx, tc.rIndex, filepath.Base(ma.Config.RulesIndex))
		}

		if len(ma.RawRules) != 0 {
			t.Errorf("[%d] Expecting no RawRules, but found %d", idx, len(ma.RawRules))
		}

		if idx != 0 {
			err = ma.LoadRulesByIndex(viper.GetString("rules.rules_index"))
			if tc.errLoadingFile && err == nil {
				t.Errorf("[%d] Expecting error when loading rules by index, but none found", idx)
			}
			if !tc.errLoadingFile && err != nil {
				t.Errorf("[%d] Expecting no error when loading rules by index, but found: %s", idx, err.Error())
			}
		}

		if len(ma.RawRules) != tc.rawRules {
			t.Errorf("[%d] Expecting to have %d RawRules, but found %d", idx, tc.rawRules, len(ma.RawRules))
		}
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
    $TCP:
      - tcp
    $HOME_NET:
      - "10.0.0.0/8"
`,
		err: false,
	}, {
		cfg: `
rules:
  variables:
    $TCP:
      - tcp
    $HOME_NET:
      - "10.0.0.0/8"
`,
		err: true,
	}}

	for idx, tc := range testCase {
		initViper(tc.cfg)

		_, err = NewManagerW()
		if tc.err && err == nil {
			t.Errorf("[%d] Expecting error but none found", idx)
		}

		if !tc.err && err != nil {
			t.Errorf("[%d] Unexpected error: %s", idx, err.Error())
		}
	}

}
