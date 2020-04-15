package rules

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hillu/go-yara"
	"github.com/jpalanco/mole/pkg/logger"
	"github.com/pkg/errors"
)

// Manager stores the rules and manages everything related with rules
type Manager struct {
	Config   *Config
	Log      *logger.Logger
	RawRules []yara.Rule
}

func NewManager() (manager *Manager, err error) {
	manager = &Manager{}
	manager.Config, err = InitConfig()

	if err != nil {
		return nil, errors.Wrap(err, "unable to initiate rules manager config")
	}

	manager.Log, _ = logger.New()

	return manager, err
}

const (
	yaraNamespace = "Mole"
	yaraFileGlob  = "*.yar"
)

var (
	varRe     = regexp.MustCompile(`(?i)\$\w+`)
	includeRe = regexp.MustCompile(`(?i)include\s+`)
)

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

	return nil
}

func (ma *Manager) LoadRulesByIndex(idxFile string) (err error) {
	yarac, err := yara.NewCompiler()
	if err != nil {
		return errors.Wrap(err, "failed to initialize YARA compiler")
	}

	ruleLines, err := fileToLines(idxFile)
	if err != nil {
		return errors.Wrapf(err, "could not open or read rule index file %s", ma.Config.RulesIndex)
	}

	cwd, err := os.Getwd()
	if err != nil {
		return errors.Wrap(err, "unable to get the curresnt working directory path")
	}

	// Index file is a bunch of lines that points to Yara rules
	// Yara rule files are relative to index file
	for _, rline := range ruleLines {
		// Remove include keyword and quotes (")
		rline = cleanUpLine(rline)

		// Get the base path of the index file
		base := filepath.Dir(idxFile)

		// Get the final rule path
		rulePath := filepath.Join(cwd, base, rline)

		// Read the rule content based on the rule file real file
		ruleString, err := ioutil.ReadFile(rulePath)

		// Parse rule and replate variables with its values
		parsedRule := parseRuleAndVars(string(ruleString), ma.Config.Vars)

		fmt.Println("RULE: ", parsedRule)
		// Add rule to the compiler
		err = yarac.AddString(parsedRule, yaraNamespace)
		if err != nil {
			return errors.Wrapf(err, "could not parse rule file %s", ma.Config.RulesIndex)
		}
	}

	rules, err := yarac.GetRules()
	if err != nil {
		return errors.Wrap(err, "failed to compile rules")
	}

	r := rules.GetRules()

	ma.RawRules = append(ma.RawRules, r...)

	return nil
}

func (ma *Manager) LoadRulesByDir(rulesFolder string) (err error) {
	yarac, err := yara.NewCompiler()
	if err != nil {
		return errors.Wrap(err, "failed to initialize YARA compiler")
	}

	files, err := loadFiles(rulesFolder)
	if err != nil {
		return errors.Wrap(err, "could not open rules directory")
	}

	for _, file := range files {
		ruleString, err := ioutil.ReadFile(file)
		if err != nil {
			return errors.Wrapf(err, "could not open rule file %s", file)
		}

		// Parse rule and replate variables with its values
		parsedRule := parseRuleAndVars(string(ruleString), ma.Config.Vars)

		// Add rule to the compiler
		err = yarac.AddString(parsedRule, yaraNamespace)
		if err != nil {
			return errors.Wrapf(err, "could not parse rule file %s", file)
		}
	}

	rules, err := yarac.GetRules()
	if err != nil {
		return errors.Wrap(err, "failed to compile rules")
	}

	r := rules.GetRules()

	ma.RawRules = append(ma.RawRules, r...)

	return nil
}

func GetRuleMetaInfo(rule yara.Rule) (metarule MetaRule, err error) {
	var ok bool
	metarule = make(MetaRule)
	for k, v := range rule.Metas() {
		metarule[k], ok = v.(string)
		if !ok {
			return metarule, errors.New("meta value is not string")
		}
	}
	return metarule, nil
}

func loadFiles(path string) ([]string, error) {
	return filepath.Glob(filepath.Join(path, yaraFileGlob))
}

func fileToLines(filePath string) (lines []string, err error) {
	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer f.Close()

	// TODO: take comments into account
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	err = scanner.Err()
	return
}

func cleanUpLine(line string) string {
	l := includeRe.ReplaceAllString(line, "")
	return strings.ReplaceAll(l, "\"", "")
}

func parseRuleAndVars(rule string, vars map[string][]string) (newRule string) {
	return varRe.ReplaceAllStringFunc(rule, func(v string) string {
		var res string = v
		if val, ok := vars[strings.ToLower(v)]; ok {
			res = strings.Join(val, ",")
		}
		return res
	})
}
