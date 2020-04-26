package rules

import (
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"
)

// RemoveCStyleComments removes C-Style comments from a byte arry
func RemoveCStyleComments(content []byte) []byte {
	// http://blog.ostermiller.org/find-comment
	ccmt := regexp.MustCompile(`/\*([^*]|[\r\n]|(\*+([^*/]|[\r\n])))*\*+/`)
	return ccmt.ReplaceAll(content, []byte(""))
}

// RemoveCppStyleComments removes C++-Style comments from a byte arry
func RemoveCppStyleComments(content []byte) []byte {
	cppcmt := regexp.MustCompile(`//.*`)
	return cppcmt.ReplaceAll(content, []byte(""))
}

// RemoveCAndCppCommentsFile removes either C-Style or C++Style comments from
// a file
func RemoveCAndCppCommentsFile(srcpath string) []byte {
	b, err := ioutil.ReadFile(srcpath)
	if err != nil {
		panic(err)
	}
	return RemoveCppStyleComments(RemoveCStyleComments(b))
}

// RemoveCAndCppComments removes either C-Style or C++Style comments from
// a file
func RemoveCAndCppComments(src string) []byte {
	return RemoveCppStyleComments(RemoveCStyleComments([]byte(src)))
}

// loadFiles loads files from path
func loadFiles(path string) ([]string, error) {
	return filepath.Glob(filepath.Join(path, yaraFileGlob))
}

// cleanUpLine is a handy function for cleaning up include line from index file
func cleanUpLine(line string) string {
	l := includeRe.ReplaceAllString(line, "")
	return strings.ReplaceAll(l, "\"", "")
}

// parseRuleAndVars replace valiables by its final value
func parseRuleAndVars(rule string, vars map[string][]string) (newRule string) {
	// Pre-processing rule to replace some vars
	rule = srcAnyPreprocRE.ReplaceAllString(rule, "src = \"$$any_addr\"")
	rule = srcPortAnyPreprocRE.ReplaceAllString(rule, "src_port = \"$$any_port\"")
	rule = dstAnyPreprocRE.ReplaceAllString(rule, "dst = \"$$any_addr\"")
	rule = dstPortAnyPreprocRE.ReplaceAllString(rule, "dst_port = \"$$any_port\"")

	return varRe.ReplaceAllStringFunc(rule, func(v string) string {
		var res string = v
		if len(vars) > 0 {
			if val, ok := vars[strings.ToLower(v)]; ok {
				res = strings.Join(val, ",")
			}
		}
		return res
	})
}

// splitRules this utility splits Yara rules so it can be processed separately
func splitRules(rulesString string) []string {
	var rules, rulesTmp []string
	var rulesTmpString string

	rulesTmpString = string(RemoveCAndCppComments(rulesString))

	rules = splitRE.Split(rulesTmpString, -1)
	if len(rules) == 1 {
		return rules
	}

	for idx, rule := range rules {
		if idx%2 == 0 {
			// Add "}"
			rule = rule + "}"
		} else {
			// Add "rule"
			rule = "rule" + rule
		}
		rulesTmp = append(rulesTmp, rule)
	}

	return rulesTmp
}
