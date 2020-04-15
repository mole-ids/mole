package engine

import (
	"github.com/k0kubun/pp"
	"github.com/pkg/errors"

	"github.com/jpalanco/mole/internal/tree"
	"github.com/jpalanco/mole/pkg/logger"
	"github.com/jpalanco/mole/pkg/rules"
)

// Engine stores the rules and proccess each packet
type Engine struct {
	Config       *Config
	RulesManager *rules.Manager
	Log          *logger.Logger
	RuleMap      tree.RuleMap
}

// Init initializes the yara engine
func New() (motor *Engine, err error) {
	motor = &Engine{}
	motor.Config, err = InitConfig()

	if err != nil {
		return nil, errors.Wrap(err, "unable to initiate engine config")
	}

	motor.Log, _ = logger.New()

	motor.RulesManager, err = rules.NewManager()
	if err != nil {
		return nil, errors.Wrap(err, "unable to initiate rules manager")
	}

	err = motor.RulesManager.LoadRules()
	if err != nil {
		return nil, errors.Wrap(err, "while loading rules")
	}

	motor.RuleMap, err = tree.TreeFromRules(motor.RulesManager.RawRules)
	if err != nil {
		return nil, errors.Wrap(err, "while generating the decicion tree")
	}

	pp.Println(motor.RuleMap)
	pp.Println(tree.Decicion)

	return motor, err
}
