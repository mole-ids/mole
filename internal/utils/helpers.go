package utils

import (
	"github.com/hillu/go-yara"
	"github.com/jpalanco/mole/internal/types"
	"github.com/pkg/errors"
)

// GetRuleMetaInfo returns the rule metadata
func GetRuleMetaInfo(rule yara.Rule) (metarule types.MetaRule, err error) {
	metarule = make(types.MetaRule)
	for _, meta := range rule.MetaList() {
		if in(meta.Identifier, types.Keywords) {
			metarule[meta.Identifier], err = types.GetNodeValue(meta.Identifier, meta.Value)
			if err != nil {
				return metarule, errors.Wrap(err, "while building rule metadata")
			}
		}
	}
	return metarule, nil
}

func in(key string, values []string) bool {
	for _, v := range values {
		if key == v {
			return true
		}
	}
	return false
}
