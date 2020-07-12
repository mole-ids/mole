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
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hillu/go-yara"
	"github.com/mole-ids/mole/internal/nodes"
	"github.com/mole-ids/mole/internal/types"
	"github.com/spf13/viper"
)

func TestInitConfigFromFile(t *testing.T) {
	testCase := []struct {
		rulesFolder string
		rulesIndex  string
		vars        map[string]string
		key         string
		value       string
		err         bool
	}{{
		rulesFolder: "",
		rulesIndex:  "",
		vars:        map[string]string{},
		key:         "",
		value:       "",
		err:         false,
	}, {
		rulesFolder: "rules",
		rulesIndex:  "",
		vars: map[string]string{
			"proto": "tcp",
		},
		key:   "proto",
		value: "tcp",
		err:   false,
	}}

	for idx, tc := range testCase {

		cfg := buildConfig(tc.rulesFolder, tc.rulesIndex, tc.vars)
		initViper(cfg)

		if d := viper.GetString("rules.rules_dir"); d != tc.rulesFolder {
			t.Errorf("[%d] Expect flag rules.rules_dir to be %s, but it was not defined", idx, tc.rulesFolder)
		}

		if d := viper.GetString("rules.rules_index"); d != tc.rulesIndex {
			t.Errorf("[%d] Expect flag rules.rules_index to be %s, but it was not defined", idx, tc.rulesIndex)
		}

		d := viper.GetStringMapString("rules.variables")

		if len(d) != len(tc.vars) {
			t.Errorf("[%d] Expected %d variables in flag rules.variables, but found: %d", idx, len(tc.vars), len(d))
		}

		if len(tc.vars) != 0 {
			if val, ok := d[tc.key]; !ok {
				t.Errorf("[%d] Expecting falg rules.variables.%s to be %s, but it is not defined", idx, tc.key, tc.value)
			} else {
				if val != tc.value {
					t.Errorf("[%d] Expecting flag rules.variables.%s to have as value %s, but found %s", idx, tc.key, tc.value, val)
				}
			}
		} else {
			if len(d) != 0 {
				t.Errorf("[%d] Expecting no variables to be defined, but they are (%d var. defined)", idx, len(d))
			}
		}
	}
}

func TestRemoveCStyleComments(t *testing.T) {
	testCase := []struct {
		comment  string
		cstyle   string
		ccpstyle string
	}{{
		comment: `This is a poc /* with C comments */
		and also has // C++ comment style`,
		cstyle:   "with C comments",
		ccpstyle: "C++ comment style",
	}}

	for idx, tc := range testCase {
		res := string(removeCStyleComments([]byte(tc.comment)))

		if strings.Contains(res, tc.cstyle) {
			t.Errorf("[%d] Unexpected C-Style comment found", idx)
		}

		if !strings.Contains(res, tc.ccpstyle) {
			t.Errorf("[%d] Expecting Cpp-Style to be in the result, but none found", idx)
		}
	}
}

func TestRemoveCppStyleComments(t *testing.T) {
	testCase := []struct {
		comment  string
		cstyle   string
		ccpstyle string
	}{{
		comment: `This is a poc /* with C comments */
		and also has // C++ comment style`,
		cstyle:   "with C comments",
		ccpstyle: "C++ comment style",
	}}

	for idx, tc := range testCase {
		res := string(removeCppStyleComments([]byte(tc.comment)))

		if !strings.Contains(res, tc.cstyle) {
			t.Errorf("[%d] Unexpected C-Style comment found", idx)
		}

		if strings.Contains(res, tc.ccpstyle) {
			t.Errorf("[%d] Expecting Cpp-Style to be in the result, but none found", idx)
		}
	}
}

func TestRemoveCAndCppComments(t *testing.T) {
	testCase := []struct {
		comment  string
		cstyle   string
		ccpstyle string
	}{{
		comment: `This is a poc /* with C comments */
		and also has // C++ comment style`,
		cstyle:   "with C comments",
		ccpstyle: "C++ comment style",
	}}

	for idx, tc := range testCase {
		res := string(removeCAndCppComments(tc.comment))

		if strings.Contains(res, tc.cstyle) {
			t.Errorf("[%d] Unexpected C-Style comment found", idx)
		}

		if strings.Contains(res, tc.ccpstyle) {
			t.Errorf("[%d] Expecting Cpp-Style to be in the result, but none found", idx)
		}
	}
}

func TestRemoveCAndCppCommentsFile(t *testing.T) {
	testCase := []struct {
		ruleData string
		path     string
		cstyle   string
		ccpstyle string
	}{{
		ruleData: `rule { /* C Style */ condition: $}`,
		path:     filepath.Join(test_dir, "rule_0"),
		cstyle:   "C Style",
		ccpstyle: "CPP Style",
	}, {
		ruleData: `rule { //* CPP Style condition: $}`,
		path:     filepath.Join(test_dir, "rule_0"),
		cstyle:   "C Style",
		ccpstyle: "CPP Style",
	}, {
		ruleData: `rule { //* CPP Style 
			/* C Style */ condition: $ }`,
		path:     filepath.Join(test_dir, "rule_0"),
		cstyle:   "C Style",
		ccpstyle: "CPP Style",
	}}

	for idx, tc := range testCase {
		ioutil.WriteFile(tc.path, []byte(tc.ruleData), os.ModePerm)

		resByte, err := removeCAndCppCommentsFile(tc.path)

		if err != nil {
			t.Errorf("[%d] Expecting no errors but found: %s", idx, err.Error())
			continue
		}

		res := string(resByte)

		if strings.Contains(res, tc.cstyle) {
			t.Errorf("[%d] Unexpected C-Style comment found", idx)
		}

		if strings.Contains(res, tc.ccpstyle) {
			t.Errorf("[%d] Unexpected Cpp-Style comment found", idx)
		}

		os.Remove(tc.path)
	}

	_, err := removeCAndCppCommentsFile("{._.}")
	if err == nil {
		t.Error("Expecting error but none found")
	}
}

func TestLoadFiles(t *testing.T) {
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	testCase := []struct {
		File *os.File
		Name string
	}{{
		Name: "0.yar",
	}, {
		Name: "1.yar",
	}, {
		Name: "2.yar",
	}}

	for _, tc := range testCase {
		tc.File, _ = os.Create(filepath.Join(dir, tc.Name))
	}

	res, err := loadFiles(dir)
	if err != nil {
		t.Errorf("Unexpected error while loading files: %s", err.Error())
	}

	if len(res) != len(testCase) {
		t.Errorf("Expecting %d results, but found %d", len(testCase), len(res))
	}

	for _, tc := range testCase {
		ok := false
		for _, fpath := range res {
			file := filepath.Base(fpath)
			if file == tc.Name {
				ok = true
			}
		}
		if !ok {
			t.Errorf("Expecting file %s to exist, but it does not", tc.Name)
		}
	}

	for _, tc := range testCase {
		tc.File.Close()
	}
}

func TestCleanUpLine(t *testing.T) {
	testCase := []struct {
		Line   string
		Result string
	}{{
		Line:   "include \"rule\"",
		Result: "rule",
	}, {
		Line:   "include    \"rule\"",
		Result: "rule",
	}, {
		Line:   "include\t\"rule\"",
		Result: "rule",
	}, {
		Line:   "       include \"rule\"",
		Result: "rule",
	}, {
		Line:   "\tinclude \"rule\"",
		Result: "rule",
	}}

	for idx, tc := range testCase {
		res := cleanUpLine(tc.Line)
		if res != tc.Result {
			t.Errorf("[%d] - Expecting result to be %s, but found %s", idx, tc.Result, res)
		}
	}
}

func TestParseRuleAndVarsSRC(t *testing.T) {
	testCase := []struct {
		Rule   string
		Result string
	}{{
		Rule:   `src="any"`,
		Result: `src = "$any_addr"`,
	}, {
		Rule:   `src = "any"`,
		Result: `src = "$any_addr"`,
	}, {
		Rule: `src	= "any"`,
		Result: `src = "$any_addr"`,
	}, {
		Rule: `src	=	"any"`,
		Result: `src = "$any_addr"`,
	}}

	var vars map[string]string
	vars = make(map[string]string)

	for idx, tc := range testCase {
		res := parseRuleAndVars(tc.Rule, vars)
		if !strings.Contains(res, tc.Result) {
			t.Errorf("[%d] - Expecting rule with %s, but found %s", idx, tc.Result, res)
		}
	}
}

func TestParseRuleAndVarsDST(t *testing.T) {
	testCase := []struct {
		Rule   string
		Result string
	}{{
		Rule:   `dst="any"`,
		Result: `dst = "$any_addr"`,
	}, {
		Rule:   `dst = "any"`,
		Result: `dst = "$any_addr"`,
	}, {
		Rule: `dst	= "any"`,
		Result: `dst = "$any_addr"`,
	}, {
		Rule: `dst	=	"any"`,
		Result: `dst = "$any_addr"`,
	}}

	var vars map[string]string
	vars = make(map[string]string)

	for idx, tc := range testCase {
		res := parseRuleAndVars(tc.Rule, vars)
		if !strings.Contains(res, tc.Result) {
			t.Errorf("[%d] - Expecting rule with %s, but found %s", idx, tc.Result, res)
		}
	}
}

func TestParseRuleAndVarsSPORT(t *testing.T) {
	testCase := []struct {
		Rule   string
		Result string
	}{{
		Rule:   `sport="any"`,
		Result: `sport = "$any_port"`,
	}, {
		Rule:   `sport = "any"`,
		Result: `sport = "$any_port"`,
	}, {
		Rule: `sport	= "any"`,
		Result: `sport = "$any_port"`,
	}, {
		Rule: `sport	=	"any"`,
		Result: `sport = "$any_port"`,
	}}

	var vars map[string]string
	vars = make(map[string]string)

	for idx, tc := range testCase {
		res := parseRuleAndVars(tc.Rule, vars)
		if !strings.Contains(res, tc.Result) {
			t.Errorf("[%d] - Expecting rule with %s, but found %s", idx, tc.Result, res)
		}
	}
}

func TestParseRuleAndVarsDPORT(t *testing.T) {
	testCase := []struct {
		Rule   string
		Result string
	}{{
		Rule:   `dport="any"`,
		Result: `dport = "$any_port"`,
	}, {
		Rule:   `dport = "any"`,
		Result: `dport = "$any_port"`,
	}, {
		Rule: `dport	= "any"`,
		Result: `dport = "$any_port"`,
	}, {
		Rule: `dport	=	"any"`,
		Result: `dport = "$any_port"`,
	}}

	var vars map[string]string
	vars = make(map[string]string)

	for idx, tc := range testCase {
		res := parseRuleAndVars(tc.Rule, vars)
		if !strings.Contains(res, tc.Result) {
			t.Errorf("[%d] - Expecting rule with %s, but found %s", idx, tc.Result, res)
		}
	}
}

func TestParseRuleAndVars(t *testing.T) {
	testCase := []struct {
		Rule   string
		Result string
	}{{
		Rule:   `proto = "$tcp"`,
		Result: `proto = "TCP"`,
	}, {
		Rule:   `src = "$HOME_NET"`,
		Result: `src = "10.0.0.0/8"`,
	}, {
		Rule:   `sport = "$HTTP_PORTS"`,
		Result: `sport = "80,443"`,
	}}

	var vars map[string]string
	vars = make(map[string]string)

	vars["$tcp"] = "TCP"
	vars["$home_net"] = "10.0.0.0/8"
	vars["$http_ports"] = "80,443"

	for idx, tc := range testCase {
		res := parseRuleAndVars(tc.Rule, vars)
		if !strings.Contains(res, tc.Result) {
			t.Errorf("[%d] - Expecting rule with %s, but found %s", idx, tc.Result, res)
		}
	}
}

func TestSplitRules(t *testing.T) {
	testCase := []struct {
		Rules  string
		Result []string
	}{{
		Rules:  `rule test1 {}`,
		Result: []string{`rule test1 {}`},
	}, {
		Rules:  `rule test1 {} rule test2 {}`,
		Result: []string{`rule test1 {}`, `rule test2 {}`},
	}, {
		Rules:  `rule test1 {}rule test2 {}`,
		Result: []string{`rule test1 {}`, `rule test2 {}`},
	}, {
		Rules: `rule test1 {

		}rule test2 {}`,
		Result: []string{`rule test1 {}`, `rule test2 {}`},
	}, {
		Rules: `rule test1 {
			
		}
		rule test2 {}`,
		Result: []string{`rule test1 {}`, `rule test2 {}`},
	}, {
		Rules: `rule test1 {
			
		}

		rule test2 {
			
		}`,
		Result: []string{`rule test1 {}`, `rule test2 {}`},
	}}

	for idx, tc := range testCase {
		res := splitRules(tc.Rules)
		if len(res) != len(tc.Result) {
			t.Errorf("[%d] - Expecting %d rules, but found %d", idx, len(tc.Result), len(res))
		}
	}
}

func TestGetRuleMetaInfo(t *testing.T) {
	testCase := []*struct {
		Rule   string
		YRule  yara.Rule
		Result types.MetaRule
		Err    bool
	}{{
		Rule: `rule T1 {
meta:
	proto = "tcp"
	src = "1.1.1.1"
	sport = "12345"
	dst = "1.1.1.1"
	dport = "12345"
strings:
	$a = "a"
condition:
	$a
}`,
		Result: make(types.MetaRule),
		Err:    false,
	}}

	for idx, tc := range testCase {
		yc, err := yara.NewCompiler()
		if err != nil {
			t.Errorf("[%d] Unexpected error when getting Yara Compiler. Err: %s", idx, err.Error())
		}

		yc.AddString(tc.Rule, "test")
		yrs, _ := yc.GetRules()
		yr := yrs.GetRules()
		tc.YRule = yr[0]
	}

	for idx, tc := range testCase {
		res, err := GetRuleMetaInfo(tc.YRule)
		if tc.Err && err == nil {
			t.Errorf("[%d] Expecting error, but none found", idx)
		}
		if !tc.Err && err != nil {
			t.Errorf("[%d] Un expected error: %s", idx, err.Error())
		}

		if len(res) != len(nodes.Keywords) {
			t.Errorf("[%d] Expecting result to have %d keys, but found %d", idx, len(nodes.Keywords), len(res))
		}

		for jdx, k := range nodes.Keywords {
			if _, ok := res[k]; !ok {
				t.Errorf("[%d]-[%d] Meta key not found, %s", idx, jdx, k)
			}
		}
	}
}
