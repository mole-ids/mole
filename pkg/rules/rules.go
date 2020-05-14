package rules

import (
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mole-ids/mole/internal/merr"
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
		return nil, errors.Wrap(err, merr.InitRulesManagerMsg)
	}

	// Load rules
	err = manager.LoadRules()
	if err != nil {
		return nil, errors.Wrap(err, merr.LoadingRulesMsg)
	}

	logger.Log.Info(logger.YaraRulesInitiatedMsg)

	return manager, err
}

// NewManagerCustom returns a new rules manager
func NewManagerCustom() (manager *Manager, err error) {
	manager = &Manager{}
	manager.Config, err = InitConfig()

	if err != nil {
		return nil, errors.Wrap(err, merr.InitRulesManagerMsg)
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
	// splitRE        = regexp.MustCompile(`(?img)rule(?:[^\n}]|\n[^\n])+`)
	splitRE = regexp.MustCompile(`(?im)}\s*rule`)

	// the following regexp are used to pre-procces the rules
	srcAnyPreprocRE     = regexp.MustCompile(`src\s*=\s*"any"`)
	srcPortAnyPreprocRE = regexp.MustCompile(`src_port\s*=\s*"any"`)
	dstAnyPreprocRE     = regexp.MustCompile(`dst\s*=\s*"any"`)
	dstPortAnyPreprocRE = regexp.MustCompile(`dst_port\s*=\s*"any"`)
)

// LoadRules load the rules defined either in the rulesIndex or rulesDir flags
func (ma *Manager) LoadRules() (err error) {
	if ma.Config.RulesIndex == "" && ma.Config.RulesFolder == "" {
		return merr.RuleOrIndexNotDefinedErr
	}

	if ma.Config.RulesIndex != "" {
		ma.LoadRulesByIndex(ma.Config.RulesIndex)
	}

	if ma.Config.RulesFolder != "" {
		ma.LoadRulesByDir(ma.Config.RulesFolder)
	}

	logger.Log.Infof(logger.YaraRulesLoadedMsg, len(ma.RawRules))

	return nil
}

// LoadRulesByIndex loads the rules defined in the `idxFile`
func (ma *Manager) LoadRulesByIndex(idxFile string) (err error) {
	// Removing comments from the file
	cleanIndex := string(RemoveCAndCppCommentsFile(idxFile))
	// Removing empty lines
	cleanIndex = removeBlanksRe.ReplaceAllString(strings.TrimSpace(cleanIndex), "\n")

	lines := strings.Split(cleanIndex, "\n")

	// Get the base path of the index file
	base := filepath.Dir(idxFile)
	// Get the absolute path for the index file from its base path
	absBase, err := filepath.Abs(base)

	if err != nil {
		return errors.Wrapf(err, merr.AbsIndexPathMsg, idxFile)
	}

	for _, iline := range lines {
		line := cleanUpLine(iline)

		// Get the final rule path
		rulePath := filepath.Join(absBase, line)

		// Read the rule content based on the rule file real file
		ruleString, err := ioutil.ReadFile(rulePath)
		if err != nil {
			return errors.Wrapf(err, merr.YaraReadFileMsg, rulePath)
		}

		ma.readRuleByRule(ruleString)
	}

	return nil
}

// LoadRulesByDir loads the rules (files *.yar) placed in `rulesFolder`
func (ma *Manager) LoadRulesByDir(rulesFolder string) (err error) {
	files, err := loadFiles(rulesFolder)
	if err != nil {
		return errors.Wrap(err, merr.OpenRulesDirMsg)
	}

	for _, file := range files {
		ruleString, err := ioutil.ReadFile(file)
		if err != nil {
			return errors.Wrapf(err, merr.OpenRuleFilesMsg, file)
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
