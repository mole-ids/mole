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
	"testing"
)

func TestNewManager(t *testing.T) {
	testCase := []struct {
		rulesFolder string
		rulesIndex  string
		vars        map[string]string
		err         bool
	}{{
		rulesFolder: "",
		rulesIndex:  "",
		vars: map[string]string{
			"home_net": "129.168.0.1",
		},
		err: true,
	}, {
		rulesFolder: "rules/",
		rulesIndex:  "",
		vars:        map[string]string{},
		err:         false,
	}, {
		rulesFolder: "",
		rulesIndex:  "index.yar",
		vars:        map[string]string{},
		err:         false,
	}, {
		rulesFolder: "index.yar",
		rulesIndex:  "",
		vars:        map[string]string{},
		err:         false,
	}, {
		rulesFolder: "index.yar",
		rulesIndex:  "",
		vars: map[string]string{
			"home_net": "192.168.1.1",
		},
		err: false,
	}, {
		rulesFolder: "index.yar",
		rulesIndex:  "",
		vars: map[string]string{
			"home_net": "192.168.1.1,192.168.1.1",
			"test":     "test1234",
		},
		err: false,
	}}

	for idx, tc := range testCase {
		cfg := buildConfig(tc.rulesFolder, tc.rulesIndex, tc.vars)
		initViper(cfg)

		ma, err := NewManager()
		if tc.err && err == nil {
			t.Errorf("[%d] Expecting error, but none found", idx)
		}

		if !tc.err && err != nil {
			t.Errorf("[%d] Expecting no error, but found: %s", idx, err.Error())
			continue
		}

		if tc.err && err != nil {
			continue
		}

		if tc.rulesFolder == "" && ma.Config.RulesFolder != tc.rulesFolder {
			t.Errorf("[%d] Expecting rule folder (%s) to match with '%s', but it does not", idx, tc.rulesFolder, ma.Config.RulesFolder)
		}

		if tc.rulesFolder != "" && ma.Config.RulesFolder != filepath.Join(test_dir, tc.rulesFolder) {
			t.Errorf("[%d] Expecting rule folder (%s) to match with '%s', but it does not", idx, filepath.Join(test_dir, tc.rulesFolder), ma.Config.RulesFolder)
		}

		if tc.rulesIndex == "" && ma.Config.RulesIndex != tc.rulesIndex {
			t.Errorf("[%d] Expecting rule index (%s) to match with %s, but it does not", idx, tc.rulesIndex, ma.Config.RulesIndex)
		}

		if tc.rulesIndex != "" && ma.Config.RulesIndex != filepath.Join(test_dir, tc.rulesIndex) {
			t.Errorf("[%d] Expecting rule index (%s) to match with %s, but it does not", idx, filepath.Join(test_dir, tc.rulesIndex), ma.Config.RulesIndex)
		}

		if tc.vars != nil {
			for k, v := range tc.vars {
				if _, ok := ma.Config.Vars[k]; ok {
					if ma.Config.Vars[k] != v {
						t.Errorf("[%d] valiables for key %s does not match and they should", idx, k)
					}
				}
			}
		}
	}
}

func TestLoadRulesByDir(t *testing.T) {
	testCase := []struct {
		rulesFolder string
		rulesIndex  string
		vars        map[string]string
		ruleName    string
		ruleContent string
		loadedRules int
		errPath     bool
		errFIndex   bool
		loadErr     bool
		err         bool
	}{{
		rulesFolder: "rules/",
		rulesIndex:  "",
		vars:        map[string]string{},
		ruleName:    "test1.yar",
		ruleContent: `rule T1 {condition: $}`,
		loadedRules: 1,
		errPath:     false,
		errFIndex:   false,
		loadErr:     false,
		err:         false,
	}, {
		rulesFolder: "rules/",
		rulesIndex:  "",
		vars:        map[string]string{},
		ruleName:    "test1.yar",
		ruleContent: `rule T1 {condition: $} rule T2 {condition: $}`,
		loadedRules: 2,
		errPath:     false,
		errFIndex:   false,
		loadErr:     false,
		err:         false,
	}, {
		rulesFolder: "rules/",
		rulesIndex:  "",
		vars:        map[string]string{},
		ruleName:    "test1.yar",
		ruleContent: `rule T1 {condition: $} rule T2 {condition: $}`,
		loadedRules: 2,
		errPath:     false,
		errFIndex:   false,
		loadErr:     false,
		err:         false,
	}}

	for idx, tc := range testCase {
		cfg := buildConfig(tc.rulesFolder, tc.rulesIndex, tc.vars)
		initViper(cfg)

		writeRule(filepath.Join(tc.rulesFolder, tc.ruleName), tc.ruleContent)

		ma, err := NewManager()

		if tc.err && err == nil {
			t.Errorf("[%d] Expecting error but none found", idx)
		}

		if !tc.err && err != nil {
			t.Errorf("[%d] Expecting no error but found: %s", idx, err.Error())
			continue
		}

		if tc.err && err != nil {
			continue
		}

		err = ma.loadRulesByDir()

		if tc.loadErr && err == nil {
			t.Errorf("[%d] Expecting error when loading rules, but none found", idx)
		}

		if !tc.loadErr && err != nil {
			t.Errorf("[%d] Expecting no error when loading rules, but found %s", idx, err.Error())
		}

		if tc.loadErr && err != nil {
			continue
		}

		if tc.rulesFolder != "" && ma.Config.RulesFolder != filepath.Join(test_dir, tc.rulesFolder) {
			t.Errorf("[%d] Expecting RulesFolder to be %s, but found %s", idx, tc.rulesFolder, ma.Config.RulesFolder)
		}

		if ma.Config.RulesIndex != "" {
			t.Errorf("[%d] Expecting RulesIndex to be '', but found %s", idx, ma.Config.RulesIndex)
		}

		if len(ma.GetRawRules()) != tc.loadedRules {
			t.Errorf("[%d] Expecting to have %d RawRules, but found %d", idx, tc.loadedRules, len(ma.RawRules))
		}
	}
}

func TestLoadRulesByIndex(t *testing.T) {
	testCase := []struct {
		rulesFolder string
		rulesIndex  string
		vars        map[string]string
		ruleName    string
		ruleContent string
		loadedRules int
		errPath     bool
		errFIndex   bool
		loadErr     bool
		err         bool
	}{{
		rulesFolder: "",
		rulesIndex:  "index.yar",
		vars:        map[string]string{},
		ruleName:    "test1.yar",
		ruleContent: `rule T1 {condition: $}`,
		loadedRules: 1,
		errPath:     false,
		errFIndex:   false,
		loadErr:     false,
		err:         false,
	}, {
		rulesFolder: "",
		rulesIndex:  "index.yar",
		vars:        map[string]string{},
		ruleName:    "test1.yar",
		ruleContent: `rule T1 {condition: $} rule T2 {condition: $}`,
		loadedRules: 2,
		errPath:     false,
		errFIndex:   false,
		loadErr:     false,
		err:         false,
	}}

	for idx, tc := range testCase {
		cfg := buildConfig(tc.rulesFolder, tc.rulesIndex, tc.vars)
		initViper(cfg)

		writeIndex(tc.rulesIndex, tc.ruleName)
		writeRule(filepath.Join(tc.rulesFolder, tc.ruleName), tc.ruleContent)

		ma, err := NewManager()

		if tc.err && err == nil {
			t.Errorf("[%d] Expecting error but none found", idx)
		}

		if !tc.err && err != nil {
			t.Errorf("[%d] Expecting no error but found: %s", idx, err.Error())
			continue
		}

		if tc.err && err != nil {
			continue
		}

		err = ma.loadRulesByIndex()

		if tc.loadErr && err == nil {
			t.Errorf("[%d] Expecting error when loading rules, but none found", idx)
		}

		if !tc.loadErr && err != nil {
			t.Errorf("[%d] Expecting no error when loading rules, but found %s", idx, err.Error())
		}

		if tc.loadErr && err != nil {
			continue
		}

		if ma.Config.RulesFolder != "" {
			t.Errorf("[%d] Expecting RulesFolder to be '', but found %s", idx, ma.Config.RulesFolder)
		}

		if tc.rulesIndex != "" && ma.Config.RulesIndex != filepath.Join(test_dir, tc.rulesIndex) {
			t.Errorf("[%d] Expecting RulesIndex to be %s, but found %s", idx, filepath.Join(test_dir, tc.rulesIndex), ma.Config.RulesIndex)
		}

		if len(ma.GetRawRules()) != tc.loadedRules {
			t.Errorf("[%d] Expecting to have %d RawRules, but found %d", idx, tc.loadedRules, len(ma.RawRules))
		}
	}
}

func TestLoadRules(t *testing.T) {
	testCase := []struct {
		rulesFolder string
		rulesIndex  string
		vars        map[string]string
		ruleName    string
		ruleContent string
		loadedRules int
		errPath     bool
		errFIndex   bool
		loadErr     bool
		err         bool
	}{{
		rulesFolder: "",
		rulesIndex:  "",
		vars:        map[string]string{},
		ruleName:    "",
		ruleContent: ``,
		loadedRules: 0,
		errPath:     true,
		errFIndex:   true,
		loadErr:     false,
		err:         true,
	}, {
		rulesFolder: "",
		rulesIndex:  "index.yar",
		vars:        map[string]string{},
		ruleName:    "test1.yar",
		ruleContent: `rule T1 {condition: $} rule T2 {condition: $}`,
		loadedRules: 2,
		errPath:     false,
		errFIndex:   false,
		loadErr:     false,
		err:         false,
	}, {
		rulesFolder: "rules/",
		rulesIndex:  "",
		vars:        map[string]string{},
		ruleName:    "test1.yar",
		ruleContent: `rule T1 {condition: $} rule T2 {condition: $}`,
		loadedRules: 2,
		errPath:     false,
		errFIndex:   false,
		loadErr:     false,
		err:         false,
	}}

	for idx, tc := range testCase {
		cfg := buildConfig(tc.rulesFolder, tc.rulesIndex, tc.vars)
		initViper(cfg)

		writeIndex(tc.rulesIndex, tc.ruleName)
		writeRule(filepath.Join(tc.rulesFolder, tc.ruleName), tc.ruleContent)

		ma, err := NewManager()
		if tc.err && err == nil {
			t.Errorf("[%d] Expecting error but none found", idx)
		}

		if !tc.err && err != nil {
			t.Errorf("[%d] Expecting no error but found: %s", idx, err.Error())
			continue
		}

		if tc.err && err != nil {
			continue
		}

		err = ma.LoadRules()
		if tc.loadErr && err == nil {
			t.Errorf("[%d] Expecting error when loading rules, but none found", idx)
		}

		if !tc.loadErr && err != nil {
			t.Errorf("[%d] Expecting no error when loading rules, but found %s", idx, err.Error())
		}

		if tc.loadErr && err != nil {
			continue
		}

		if tc.rulesFolder != "" && ma.Config.RulesFolder != filepath.Join(test_dir, tc.rulesFolder) {
			t.Errorf("[%d] Expecting RulesFolder to be '%s', but found %s", idx, filepath.Join(test_dir, tc.rulesFolder), ma.Config.RulesFolder)
		}

		if tc.rulesIndex != "" && ma.Config.RulesIndex != filepath.Join(test_dir, tc.rulesIndex) {
			t.Errorf("[%d] Expecting RulesIndex to be %s, but found %s", idx, filepath.Join(test_dir, tc.rulesIndex), ma.Config.RulesIndex)
		}

		if len(ma.GetRawRules()) != tc.loadedRules {
			t.Errorf("[%d] Expecting to have %d RawRules, but found %d", idx, tc.loadedRules, len(ma.RawRules))
		}
	}
}
