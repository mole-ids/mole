package types

import "github.com/hillu/go-yara"

// NodeValue is the interface that all nodes in the decision tree needs to meet
type NodeValue interface {
	Match(NodeValue) bool
	GetKey() string
	GetValue() string
}

// MetaRule defines yara rule metadata
// MetaRule use as key the Keywords defined also in this package
type MetaRule map[string]NodeValue

// RuleMapScanner defines the Yara scanners to execute for each ID
type RuleMapScanner map[string]*yara.Scanner

const (
	// YaraNamespace the Yara rules namespace
	YaraNamespace = "Mole"
)
