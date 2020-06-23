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
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hillu/go-yara"
	"github.com/mole-ids/mole/internal/types"
	"github.com/mole-ids/mole/internal/utils"
	"github.com/pkg/errors"
)

// GetRuleMetaInfo returns the rule metadata
func GetRuleMetaInfo(rule yara.Rule) (metarule types.MetaRule, err error) {
	metarule = make(types.MetaRule)
	for _, meta := range rule.MetaList() {
		if utils.InStrings(meta.Identifier, types.Keywords) {
			// This will never generate an error becauses meta.Identifieris double
			// checked in the previous conditional
			metarule[meta.Identifier], _ = types.GetNodeValue(meta.Identifier, meta.Value)
		}
	}

	for k, v := range metarule {
		if v == nil {
			return metarule, errors.Errorf(WrongMetadataFieldMsg, k)
		}
	}

	for _, k := range types.Keywords {
		if _, ok := metarule[k]; !ok {
			return metarule, errors.Errorf(KeywordsNotMeetMsg, k)
		}
	}

	return metarule, nil
}

// removeCStyleComments removes C-Style comments from a byte arry
func removeCStyleComments(content []byte) []byte {
	// http://blog.ostermiller.org/find-comment
	ccmt := regexp.MustCompile(`/\*([^*]|[\r\n]|(\*+([^*/]|[\r\n])))*\*+/`)
	return ccmt.ReplaceAll(content, []byte(""))
}

// removeCppStyleComments removes C++-Style comments from a byte arry
func removeCppStyleComments(content []byte) []byte {
	cppcmt := regexp.MustCompile(`//.*`)
	return cppcmt.ReplaceAll(content, []byte(""))
}

// removeCAndCppCommentsFile removes either C-Style or C++Style comments from
// a file
func removeCAndCppCommentsFile(srcpath string) ([]byte, error) {
	b, err := ioutil.ReadFile(srcpath)
	if err != nil {
		return b, errors.Wrap(err, WhileReadingFileMsg)
	}
	return removeCppStyleComments(removeCStyleComments(b)), nil
}

// removeCAndCppComments removes either C-Style or C++Style comments from
// a file
func removeCAndCppComments(src string) []byte {
	return removeCppStyleComments(removeCStyleComments([]byte(src)))
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
func parseRuleAndVars(rule string, vars map[string]string) (newRule string) {
	// Pre-processing rule to replace some vars
	rule = srcAnyPreprocRE.ReplaceAllString(rule, "src = \"$$any_addr\"")
	rule = srcPortAnyPreprocRE.ReplaceAllString(rule, "sport = \"$$any_port\"")
	rule = dstAnyPreprocRE.ReplaceAllString(rule, "dst = \"$$any_addr\"")
	rule = dstPortAnyPreprocRE.ReplaceAllString(rule, "dport = \"$$any_port\"")

	rule = protoCapPrepocRE.ReplaceAllStringFunc(rule, func(v string) string {
		return protoCapPrepocInternalRE.ReplaceAllStringFunc(v, func(vv string) string {
			return strings.ToLower(vv)
		})
	})

	return varRe.ReplaceAllStringFunc(rule, func(v string) string {
		var res string = v
		if len(vars) > 0 {
			if val, ok := vars[strings.ToLower(v)]; ok {
				res = val
			}
		}
		return res
	})
}

// splitRules this utility splits Yara rules so it can be processed separately
func splitRules(rulesString string) []string {
	// TODO: this need to be improved. At the moment this can be considered as
	// a workarround. It should be a better way to split up the rules one by one
	var rules, rulesTmp []string
	var rulesTmpString string

	rulesTmpString = string(removeCAndCppComments(rulesString))

	rules = splitRE.Split(rulesTmpString, -1)
	if len(rules) == 1 {
		return rules
	}

	for idx, rule := range rules {
		if idx == 0 {
			// Add "}"
			rule = rule + "}"
		} else if idx == len(rules)-1 {
			// Add "rule"
			rule = "rule" + rule
		} else {
			rule = "rule" + rule + "}"
		}
		rulesTmp = append(rulesTmp, rule)
	}

	return rulesTmp
}

func getPathPrefix(b, p string) (string, error) {
	if b == "" {
		return filepath.Abs(p)
	}
	return filepath.Abs(filepath.Join(b, p))
}
