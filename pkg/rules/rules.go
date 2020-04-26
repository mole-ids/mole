package rules

import (
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jpalanco/mole/pkg/logger"
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
		return nil, errors.Wrap(err, "unable to initiate rules manager config")
	}

	// Load rules
	err = manager.LoadRules()
	if err != nil {
		return nil, errors.Wrap(err, "while loading rules")
	}

	logger.Log.Info("yara rules loaded successfully")

	return manager, err
}

// NewManagerCustom returns a new rules manager
func NewManagerCustom() (manager *Manager, err error) {
	manager = &Manager{}
	manager.Config, err = InitConfig()

	if err != nil {
		return nil, errors.Wrap(err, "unable to initiate rules manager config")
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
		return errors.New("either a rule index or rule folder have to be defined")
	}

	if ma.Config.RulesIndex != "" {
		ma.LoadRulesByIndex(ma.Config.RulesIndex)
	}

	if ma.Config.RulesFolder != "" {
		ma.LoadRulesByDir(ma.Config.RulesFolder)
	}

	logger.Log.Infof("loaded %d rules", len(ma.RawRules))

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
		return errors.Wrapf(err, "unable to get the absolute path for index file %s", idxFile)
	}

	for _, iline := range lines {
		line := cleanUpLine(iline)

		// Get the final rule path
		rulePath := filepath.Join(absBase, line)

		// Read the rule content based on the rule file real file
		ruleString, err := ioutil.ReadFile(rulePath)
		if err != nil {
			return errors.Wrapf(err, "unable to read the yara rule %s", rulePath)
		}

		ma.readRuleByRule(ruleString)
	}

	return nil
}

// LoadRulesByDir loads the rules (files *.yar) placed in `rulesFolder`
func (ma *Manager) LoadRulesByDir(rulesFolder string) (err error) {
	files, err := loadFiles(rulesFolder)
	if err != nil {
		return errors.Wrap(err, "could not open rules directory")
	}

	for _, file := range files {
		ruleString, err := ioutil.ReadFile(file)
		if err != nil {
			return errors.Wrapf(err, "could not open rule file %s", file)
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
