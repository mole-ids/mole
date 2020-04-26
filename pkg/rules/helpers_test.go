package rules

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

const (
	rulesDir   = "./rules"
	rulesIndex = "index.yar"

	cstyle   = "C-Style comment"
	cppstyle = "Cpp-Style comment"

	rule = `
/* C-Style comment */
rule ExampleRule
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

	config = `
rules:
  rules_dir: ./rules
  rules_index: index.yar
  variables:
    $TCP:
      - tcp
    $HOME_NET:
      - "10.0.0.0/8"
`
)

func TestInitConfigFromFile(t *testing.T) {
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	name := "mole"
	ext := "yml"
	fname := name + "." + ext
	fpath := filepath.Join(dir, fname)

	ioutil.WriteFile(fpath, []byte(config), 0655)

	viper.Reset()
	viper.SetConfigType("yaml")
	viper.SetConfigName(name)
	viper.AddConfigPath(dir)

	err = viper.ReadInConfig()
	if err != nil {
		t.Errorf("Fatal error config file: %s", err)
	}

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
	res := string(RemoveCStyleComments([]byte(rule)))

	if strings.Contains(res, cstyle) {
		t.Error("Unexpected C-Style comment found")
	}

	if !strings.Contains(res, cppstyle) {
		t.Error("Expecting Cpp-Style to be in the result, but none found")
	}

	if strings.Count(res, "strings") != 2 {
		t.Errorf("Expecting keyword 'strings' appear twice, but found %d", strings.Count(res, "strings"))
	}
}

func TestRemoveCppStyleComments(t *testing.T) {
	res := string(RemoveCppStyleComments([]byte(rule)))

	if strings.Contains(res, cppstyle) {
		t.Error("Unexpected Cpp-Style comment found")
	}

	if !strings.Contains(res, cstyle) {
		t.Error("Expecting Cpp-Style to be in the result, but none found")
	}

	if strings.Count(res, "strings") != 2 {
		t.Errorf("Expecting keyword 'strings' appear twice, but found %d", strings.Count(res, "strings"))
	}
}

func TestRemoveCAndCppComments(t *testing.T) {
	res := string(RemoveCAndCppComments(rule))

	if strings.Contains(res, cstyle) {
		t.Error("Unexpected C-Style comment found")
	}

	if strings.Contains(res, cppstyle) {
		t.Error("Unexpected Cpp-Style comment found")
	}

	if strings.Count(res, "strings") != 1 {
		t.Errorf("Expecting keyword 'strings' appear twice, but found %d", strings.Count(res, "strings"))
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
			t.Errorf("%d - Expecting result to be %s, but found %s", idx, tc.Result, res)
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
			t.Errorf("%d - Expecting rule with %s, but found %s", idx, tc.Result, res)
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
			t.Errorf("%d - Expecting rule with %s, but found %s", idx, tc.Result, res)
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
			t.Errorf("%d - Expecting rule with %s, but found %s", idx, tc.Result, res)
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
			t.Errorf("%d - Expecting rule with %s, but found %s", idx, tc.Result, res)
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
			t.Errorf("%d - Expecting rule with %s, but found %s", idx, tc.Result, res)
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
			t.Errorf("%d - Expecting %d rules, but found %d", idx, len(tc.Result), len(res))
		}
	}
}
