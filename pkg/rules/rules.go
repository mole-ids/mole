package rules

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jpalanco/mole/pkg/logger"
	"github.com/pkg/errors"
)

// Manager stores the rules and manages everything related with rules
type Manager struct {
	Config   *Config
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

const (
	yaraFileGlob = "*.yar"
)

var (
	varRe          = regexp.MustCompile(`(?i)\$\w+`)
	includeRe      = regexp.MustCompile(`(?i)include\s+`)
	removeBlanksRe = regexp.MustCompile(`[\t\r\n]+`)
	// splitRE        = regexp.MustCompile(`(?img)rule(?:[^\n}]|\n[^\n])+`)
	splitRE = regexp.MustCompile(`(?im)}\s*rule`)
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
		ma.LoadRulesByIndex(ma.Config.RulesFolder)
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

	cwd, err := os.Getwd()
	if err != nil {
		return errors.Wrap(err, "unable to get the curresnt working directory path")
	}

	for _, iline := range lines {
		line := cleanUpLine(iline)
		// Get the base path of the index file
		base := filepath.Dir(idxFile)

		// Get the final rule path
		rulePath := filepath.Join(cwd, base, line)

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
	// TODO: This need to be redone, because rules need to be loaded one by one
	// than means included rules needs to be parsed and processed one by one.
	// One rule is not he file, one rule is a propper Yara rule.

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

// loadFiles loads files from path
func loadFiles(path string) ([]string, error) {
	return filepath.Glob(filepath.Join(path, yaraFileGlob))
}

// cleanUpLine handy function for cleaning up include line from index file
func cleanUpLine(line string) string {
	l := includeRe.ReplaceAllString(line, "")
	return strings.ReplaceAll(l, "\"", "")
}

// parseRuleAndVars replace valiables by its final value
func parseRuleAndVars(rule string, vars map[string][]string) (newRule string) {
	return varRe.ReplaceAllStringFunc(rule, func(v string) string {
		var res string = v
		if val, ok := vars[strings.ToLower(v)]; ok {
			res = strings.Join(val, ",")
		}
		return res
	})
}

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
			// Add }
			rule = rule + "}"
		} else {
			// Add rule
			rule = "rule" + rule
		}
		rulesTmp = append(rulesTmp, rule)
	}

	return rulesTmp
}
