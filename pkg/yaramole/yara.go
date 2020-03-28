package yaramole

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hillu/go-yara"
	"github.com/jpalanco/mole/conf"
)

const (
	yaraNamespace = "moleSpace"
	yaraFileGlob  = "*.yar"
)

// GetYaraScanner returns a go-yara scanner with rules deom `rulesDir` loaded into it
func GetYaraScanner(config *conf.Config) (scanner *yara.Scanner, err error) {
	logger, err := conf.ConfigureLogging(config.LogConfig)
	if err != nil {
		e := fmt.Sprintf("unable to configure the logger", err.Error())
		return nil, errors.New(e)
	}
	yarac, err := yara.NewCompiler()
	if err != nil {
		e := fmt.Sprintf("failed to initialize YARA compiler: %s", err.Error())
		return nil, errors.New(e)
	}

	logger.Infof("loading rules from %s", config.RulesDir)
	files, err := loadFiles(config.RulesDir)
	if err != nil {
		e := fmt.Sprintf("could not open rules directory: %s", err.Error())
		return nil, errors.New(e)
	}

	for _, file := range files {
		if !strings.HasSuffix(file, "demo.yar") {
			continue
		}

		f, err := os.Open(file)
		if err != nil {
			e := fmt.Sprintf("could not open rule file %s: %s", file, err.Error())
			return nil, errors.New(e)
		}

		err = yarac.AddFile(f, yaraNamespace)
		if err != nil {
			f.Close()
			e := fmt.Sprintf("could not parse rule file %s: %s", file, err.Error())
			return nil, errors.New(e)
		}
		logger.Infow("added rule", "rule", file)
		f.Close()
	}

	rules, err := yarac.GetRules()
	if err != nil {
		e := fmt.Sprintf("failed to compile rules: %s", err.Error())
		return nil, errors.New(e)
	}

	scanner, err = yara.NewScanner(rules)
	if err != nil {
		e := fmt.Sprintf("failed to get yara scanner: %s", err.Error())
		return nil, errors.New(e)
	}
	// scanner = scan.SetCallback(cb)
	return
}

func loadFiles(path string) ([]string, error) {
	return filepath.Glob(filepath.Join(path, yaraFileGlob))
}
