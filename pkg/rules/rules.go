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
	"time"

	"github.com/mole-ids/mole/pkg/logger"
	"github.com/pkg/errors"
)

// Manager stores the rules and manages everything related with rules
type Manager struct {
	// Config manger's configuration most of its values come from the arguments
	// or configuration file
	Config *Config
	// RawRules store all Yara rules
	RawRules []string
}

// NewManager returns a new rules manager
func NewManager() (manager *Manager, err error) {
	manager = &Manager{}
	manager.Config, err = InitConfig()

	if err != nil {
		return nil, errors.Wrap(err, RulesManagerInitFailedMsg)
	}

	return manager, err
}

const (
	yaraFileGlob = "*.yar"
)

var (
	varRe          = regexp.MustCompile(`(?i)\$\w+`)
	includeRe      = regexp.MustCompile(`(?i)\s*include\s+`)
	removeBlanksRe = regexp.MustCompile(`[\t\r\n]+`)
	splitRE        = regexp.MustCompile(`(?im)}\s*rule`)

	// the following regexp are used to pre-procces the rules
	srcAnyPreprocRE          = regexp.MustCompile(`src\s*=\s*"any"`)
	srcPortAnyPreprocRE      = regexp.MustCompile(`sport\s*=\s*"any"`)
	dstAnyPreprocRE          = regexp.MustCompile(`dst\s*=\s*"any"`)
	dstPortAnyPreprocRE      = regexp.MustCompile(`dport\s*=\s*"any"`)
	protoCapPrepocRE         = regexp.MustCompile(`proto\s*=\s*"(\w+)"`)
	protoCapPrepocInternalRE = regexp.MustCompile(`"\w+"`)
)

// LoadRules load the rules defined either in the rulesIndex or rulesDir flags
func (ma *Manager) LoadRules() (err error) {
	if ma.Config.RulesIndex == "" && ma.Config.RulesFolder == "" {
		return ErrIndexOrRuleFolderPathRequired
	}

	start := time.Now()
	if ma.Config.RulesIndex != "" {
		logger.Log.Infof(IndexFileUsedMsg, ma.Config.RulesIndex)
		err = ma.loadRulesByIndex()
		if err != nil {
			return errors.Wrap(err, WhileLodingRulesByIndexMsg)
		}
	}

	if ma.Config.RulesFolder != "" {
		logger.Log.Infof(RulesFolderUsedMsg, ma.Config.RulesFolder)
		err = ma.loadRulesByDir()
		if err != nil {
			return errors.Wrap(err, WhileLodingRulesByFolderMsg)
		}
	}

	elapsed := time.Since(start)
	logger.Log.Infof(TimeElapsedLoadingRulesMsg, len(ma.RawRules), elapsed.Seconds())

	return nil
}

// loadRulesByIndex loads the rules defined in the `idxFile`
func (ma *Manager) loadRulesByIndex() (err error) {
	idxFile := ma.Config.RulesIndex

	// Removing comments from the file
	res, err := removeCAndCppCommentsFile(idxFile)
	if err != nil {
		return errors.Wrap(err, CleanUpRuleMsg)
	}

	cleanIndex := string(res)

	// Removing empty lines
	cleanIndex = removeBlanksRe.ReplaceAllString(strings.TrimSpace(cleanIndex), "\n")
	lines := strings.Split(cleanIndex, "\n")

	// Get the base path of the index file
	base := filepath.Dir(idxFile)

	for _, iline := range lines {
		line := cleanUpLine(iline)

		// Get the final rule path
		rulePath := filepath.Join(base, line)

		// Read the rule content based on the rule file real file
		ruleString, err := ioutil.ReadFile(rulePath)
		if err != nil {
			return errors.Wrapf(err, ReadRuleFileFailedMsg, rulePath)
		}

		ma.readRuleByRule(ruleString)
	}

	return nil
}

// loadRulesByDir loads the rules (files *.yar) placed in `rulesFolder`
func (ma *Manager) loadRulesByDir() (err error) {
	rulesFolder := ma.Config.RulesFolder

	files, err := loadFiles(rulesFolder)
	if err != nil {
		return errors.Wrap(err, ReadRulesFolderFailedMsg)
	}

	for _, file := range files {
		ruleString, err := ioutil.ReadFile(file)
		if err != nil {
			return errors.Wrapf(err, ReadRuleFileFailedMsg, file)
		}

		ma.readRuleByRule(ruleString)
	}

	return nil
}

func (ma *Manager) readRuleByRule(rule []byte) {
	rules := splitRules(string(rule))

	for _, rule := range rules {
		newRule := parseRuleAndVars(rule, ma.Config.Vars)
		ma.RawRules = append(ma.RawRules, newRule)
	}
}

// GetRawRules returns the loaded rules in raw format
func (ma *Manager) GetRawRules() []string {
	return ma.RawRules
}
