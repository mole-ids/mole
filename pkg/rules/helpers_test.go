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
	"github.com/mole-ids/mole/internal/types"
	"github.com/spf13/viper"
)

func TestInitConfigFromFile(t *testing.T) {
	initViper(test_config)

	if d := viper.GetString("rules.rules_dir"); d != "./rules" {
		t.Errorf("Flag rules.rules_dir was not defined :: %s", viper.GetString("rules.rules_dir"))
	}

	if d := viper.GetString("rules.rules_index"); d != "index.yar" {
		t.Error("Flag rules.rules_index was not defined")
	}

	d := viper.GetStringMapStringSlice("rules.variables")
	if len(d) != 2 {
		t.Error("Flag rules.variables was not defined")
	}

	if val, ok := d["$tcp"]; !ok {
		t.Error("Falg rules.variables.$tcp is not defined")
	} else {
		if len(val) != 1 {
			t.Errorf("Expecting flag rules.variables[$tcp] to have one value, but found %d", len(val))
		}
		if len(val) > 0 && val[0] != "tcp" {
			t.Errorf("Expecting flag rules.variables[$tcp] to have as value tcp, but found %s", val[0])
		}
	}
}

func TestRemoveCStyleComments(t *testing.T) {
	res := string(RemoveCStyleComments([]byte(test_rule)))

	if strings.Contains(res, test_cstyle) {
		t.Error("Unexpected C-Style comment found")
	}

	if !strings.Contains(res, test_cppstyle) {
		t.Error("Expecting Cpp-Style to be in the result, but none found")
	}

	if strings.Count(res, "strings") != 2 {
		t.Errorf("Expecting keyword 'strings' appear twice, but found %d", strings.Count(res, "strings"))
	}
}

func TestRemoveCppStyleComments(t *testing.T) {
	res := string(RemoveCppStyleComments([]byte(test_rule)))

	if strings.Contains(res, test_cppstyle) {
		t.Error("Unexpected Cpp-Style comment found")
	}

	if !strings.Contains(res, test_cstyle) {
		t.Error("Expecting Cpp-Style to be in the result, but none found")
	}

	if strings.Count(res, "strings") != 2 {
		t.Errorf("Expecting keyword 'strings' appear twice, but found %d", strings.Count(res, "strings"))
	}
}

func TestRemoveCAndCppComments(t *testing.T) {
	res := string(RemoveCAndCppComments(test_rule))

	if strings.Contains(res, test_cstyle) {
		t.Error("Unexpected C-Style comment found")
	}

	if strings.Contains(res, test_cppstyle) {
		t.Error("Unexpected Cpp-Style comment found")
	}

	if strings.Count(res, "strings") != 1 {
		t.Errorf("Expecting keyword 'strings' appear twice, but found %d", strings.Count(res, "strings"))
	}
}

func TestRemoveCAndCppCommentsFile(t *testing.T) {
	f, err := ioutil.TempFile("", "")
	if err != nil {
		t.Error("Unexpected error while creating temp file")
	}

	_, err = f.WriteString(test_rule)
	if err != nil {
		t.Error("Unexpected error while creating temp file")
	}

	fname := f.Name()

	resByte, err := RemoveCAndCppCommentsFile(fname)
	if err != nil {
		t.Errorf("Expecting no errors but found: %s", err.Error())
	}

	res := string(resByte)

	if strings.Contains(res, test_cstyle) {
		t.Error("Unexpected C-Style comment found")
	}

	if strings.Contains(res, test_cppstyle) {
		t.Error("Unexpected Cpp-Style comment found")
	}

	if strings.Count(res, "strings") != 1 {
		t.Errorf("Expecting keyword 'strings' appear twice, but found %d", strings.Count(res, "strings"))
	}

	resByte, err = RemoveCAndCppCommentsFile(fname + "_")
	if err == nil {
		t.Error("Expecting error but none found")
	}
}

func Test_loadFiles(t *testing.T) {
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

func Test_cleanUpLine(t *testing.T) {
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

func Test_parseRuleAndVarsSRC(t *testing.T) {
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

	var vars map[string][]string
	vars = make(map[string][]string)

	for idx, tc := range testCase {
		res := parseRuleAndVars(tc.Rule, vars)
		if !strings.Contains(res, tc.Result) {
			t.Errorf("[%d] - Expecting rule with %s, but found %s", idx, tc.Result, res)
		}
	}
}

func Test_parseRuleAndVarsDST(t *testing.T) {
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

	var vars map[string][]string
	vars = make(map[string][]string)

	for idx, tc := range testCase {
		res := parseRuleAndVars(tc.Rule, vars)
		if !strings.Contains(res, tc.Result) {
			t.Errorf("[%d] - Expecting rule with %s, but found %s", idx, tc.Result, res)
		}
	}
}

func Test_parseRuleAndVarsSRC_PORT(t *testing.T) {
	testCase := []struct {
		Rule   string
		Result string
	}{{
		Rule:   `src_port="any"`,
		Result: `src_port = "$any_port"`,
	}, {
		Rule:   `src_port = "any"`,
		Result: `src_port = "$any_port"`,
	}, {
		Rule: `src_port	= "any"`,
		Result: `src_port = "$any_port"`,
	}, {
		Rule: `src_port	=	"any"`,
		Result: `src_port = "$any_port"`,
	}}

	var vars map[string][]string
	vars = make(map[string][]string)

	for idx, tc := range testCase {
		res := parseRuleAndVars(tc.Rule, vars)
		if !strings.Contains(res, tc.Result) {
			t.Errorf("[%d] - Expecting rule with %s, but found %s", idx, tc.Result, res)
		}
	}
}

func Test_parseRuleAndVarsDST_PORT(t *testing.T) {
	testCase := []struct {
		Rule   string
		Result string
	}{{
		Rule:   `dst_port="any"`,
		Result: `dst_port = "$any_port"`,
	}, {
		Rule:   `dst_port = "any"`,
		Result: `dst_port = "$any_port"`,
	}, {
		Rule: `dst_port	= "any"`,
		Result: `dst_port = "$any_port"`,
	}, {
		Rule: `dst_port	=	"any"`,
		Result: `dst_port = "$any_port"`,
	}}

	var vars map[string][]string
	vars = make(map[string][]string)

	for idx, tc := range testCase {
		res := parseRuleAndVars(tc.Rule, vars)
		if !strings.Contains(res, tc.Result) {
			t.Errorf("[%d] - Expecting rule with %s, but found %s", idx, tc.Result, res)
		}
	}
}

func Test_parseRuleAndVars(t *testing.T) {
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
		Rule:   `src_port = "$HTTP_PORTS"`,
		Result: `src_port = "80,443"`,
	}}

	var vars map[string][]string
	vars = make(map[string][]string)

	vars["$tcp"] = []string{"TCP"}
	vars["$home_net"] = []string{"10.0.0.0/8"}
	vars["$http_ports"] = []string{"80", "443"}

	for idx, tc := range testCase {
		res := parseRuleAndVars(tc.Rule, vars)
		if !strings.Contains(res, tc.Result) {
			t.Errorf("[%d] - Expecting rule with %s, but found %s", idx, tc.Result, res)
		}
	}
}

func Test_splitRules(t *testing.T) {
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
	src_port = "12345"
	dst = "1.1.1.1"
	dst_port = "12345"
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

		if len(res) != len(types.Keywords) {
			t.Errorf("[%d] Expecting result to have %d keys, but found %d", idx, len(types.Keywords), len(res))
		}

		for jdx, k := range types.Keywords {
			if _, ok := res[k]; !ok {
				t.Errorf("[%d]-[%d] Meta key not found, %s", idx, jdx, k)
			}
		}
	}
}
