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
package tree

import "errors"

const (
	RuleMapBuiltMsg           = "building rules map"
	CompileYaraRuleFailedMsg  = "Mole could not compile a yara rule, because"
	YaraRuleMetadataMsg       = "while getting metadata info from %s got"
	AddingRuleMsg             = "adding rule: proto:%s | src:%s | sport:%s | dst:%s | dport:%s"
	InsertRuleFailedMsg       = "unable to insert rule %s, because"
	NewYaraCompilerMsg        = "while creating yara compiler got"
	CompiledRulesNotFoundMsg  = "unable to get compiled rules"
	WhileGettingNodeByTypeMsg = "while getting node by type got"
	DecisionTreeNotInitMsg    = "decision tree not initialized"
	CreateTreeNodeAtLevelMsg  = "when creating node at level %d with key %s got"
	SolutionNotFoundMsg       = "solution not found"
)

var (
	ErrCompiledRulesNotFound = errors.New(CompiledRulesNotFoundMsg)
	ErrDecisionTreeNotInit   = errors.New(DecisionTreeNotInitMsg)
	ErrSolutionNotFound      = errors.New(SolutionNotFoundMsg)
)
