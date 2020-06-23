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

import (
	"github.com/hillu/go-yara"
	"github.com/pkg/errors"

	"github.com/mole-ids/mole/internal/types"
	"github.com/mole-ids/mole/pkg/logger"
	"github.com/mole-ids/mole/pkg/rules"
)

// Tree implemnts a n-ary tree for storing the decision tree
type Tree struct {
	// Value is the node's value
	Value types.NodeValue
	// Parent points to the parent node
	Parent *Tree
	// Next points to the next node in the same lavel
	Next *Tree
	// Children point to the child node and so the next level in the tree
	Children *Tree
}

// RuleMap maps between ID and a bunch of Yara rules
// type RuleMap map[string]yara.Rule

var (
	// Decision is the decision tree
	Decision *Tree
)

// FromRules builds the Decision tree from scratch and returns types.RuleMapScanner
// which is a map that define what Yara rule set execute for each id
func FromRules(rulesList []string) (ruleMap types.RuleMapScanner, err error) {
	logger.Log.Debug(RuleMapBuiltMsg)
	// initialize the result map
	ruleMap = make(types.RuleMapScanner)
	// used as a middleware for extracting ara rule Metadata. These rules are
	// not used for anything else
	middleMap := make(map[string]*yara.Compiler)

	// Initialize the decision tree
	Decision = New(types.NodeRoot())

	// Loop though the whole list of rules
	for _, rule := range rulesList {
		// compile each rule
		cr, err := yara.Compile(rule, map[string]interface{}{})
		if err != nil {
			return nil, errors.Wrap(err, CompileYaraRuleFailedMsg)
		}

		// crules should only contain one rule
		crule := cr.GetRules()
		yrule := crule[0]

		// Extracting rule metadata
		meta, err := rules.GetRuleMetaInfo(yrule)
		if err != nil {
			return nil, errors.Wrapf(err, YaraRuleMetadataMsg, yrule.Identifier())
		}

		logger.Log.Debugf(AddingRuleMsg, meta["proto"].GetValue(), meta["src"].GetValue(), meta["sport"].GetValue(), meta["dst"].GetValue(), meta["dport"].GetValue())

		// Insert the node according to its metadata
		idNode, _, err := insertRule(Decision, 0, types.Keywords, meta)
		if err != nil {
			return nil, errors.Wrapf(err, InsertRuleFailedMsg, yrule.Identifier())
		}

		// If there is not error, then get the identifier
		id := idNode.Value.GetValue()

		// Build a middleware map. This constructs a Yara compiler for each
		// map entry, this way it is easy to add rules to the compiler or
		// rule set based on the id.
		if val, ok := middleMap[id]; ok {
			val.AddString(rule, types.YaraNamespace)
		} else {
			c, err := yara.NewCompiler()
			if err != nil {
				return nil, errors.Wrap(err, NewYaraCompilerMsg)
			}
			c.AddString(rule, types.YaraNamespace)
			middleMap[id] = c
		}
	}

	// The compiler does not allow to scan so a scanner needs to be used insted.
	// So the ruleMap has a Yara scanner with the rules for each id.
	for k, v := range middleMap {
		r, err := v.GetRules()
		if err != nil {
			return nil, ErrCompiledRulesNotFound
		}

		ruleMap[k], err = yara.NewScanner(r)
		if err != nil {
			return nil, errors.Wrap(err, NewYaraCompilerMsg)
		}
	}
	return ruleMap, nil
}

// New returns a new Tree with a root node
func New(value types.NodeValue) *Tree {
	// TODO: control the error when casting
	nValue := value.(types.NodeValue)

	return &Tree{
		Value:    nValue,
		Parent:   nil,
		Next:     nil,
		Children: nil,
	}
}

// GetNodeByType returns a node based on the type of node
func GetNodeByType(key string, value interface{}) (*Tree, error) {
	nv, err := types.GetNodeValue(key, value)
	if err != nil {
		return New(nv), errors.Wrap(err, WhileGettingNodeByTypeMsg)
	}
	return New(nv), nil
}

// InsertRule inserts Yara rule and generates an ID
func InsertRule(lvl int, keys []string, rule types.MetaRule) (nodeID *Tree, ok bool, err error) {
	if Decision == nil {
		return nil, false, ErrDecisionTreeNotInit
	}
	return insertRule(Decision, lvl, keys, rule)
}

// insertRule does the true insert
func insertRule(tree *Tree, lvl int, keys []string, rule types.MetaRule) (nodeID *Tree, ok bool, err error) {
	if tree.Children == nil {
		// This happens when a new branch is being built up

		// Wuhile level is blow keys length we can add nodes saftly
		if lvl < len(keys) {
			// Getting a new node. The new node will be the new children node
			node, err := GetNodeByType(keys[lvl], rule[keys[lvl]].GetValue())
			if err != nil {
				return nil, false, errors.Wrapf(err, CreateTreeNodeAtLevelMsg, lvl, keys[lvl])
			}

			// Setting up the node with pointers
			node.Parent = tree
			tree.Children = node

			// if level hasn't reached the max value, keep inserting nodes
			return insertRule(node, lvl+1, keys, rule)
		}
		// If we've reached the lastest node and it was inserted successfully,
		// then we need to add an extra node. The extra node will be the `id` node.
		idNode, err := GetNodeByType("id", nil)
		idNode.Parent = tree
		tree.Children = idNode

		return idNode, true, err
	}
	// When there is a child is because the branch is already populated

	/* There are two scenarios here.
	1- The node has just one child.
	In this case, we have to compare the node value with the new node value,
	if they match, then we should not insert a node in this level and
	carry on with the next node at next level, otherwie the new node should
	be inserted at this level.
	*/

	// Build a temp node, with the values of the new node
	tmpNode, err := GetNodeByType(keys[lvl], rule[keys[lvl]].GetValue())
	if err != nil {
		return nil, false, err
	}

	var matched bool = true
	// Loop through all children
	var current *Tree = nil
	child := tree.Children
	for child != nil {
		current = child
		child = current.Next

		// Checking node value against new node value
		if match := current.Value.Match(tmpNode.Value); match {
			// Node values match so we should jump the current level and
			// carry on with the next one
			matched = true
			break // Shouldn't be more nodes with the same value
		} else {
			// Values does not match so insert the new node as child
			matched = false
		}
	}

	if !matched {
		// Doing the proper insert when no match found
		tmpNode.Parent = current.Parent
		tmpNode.Next = current.Next
		current.Next = tmpNode

		if lvl+1 == len(keys) {
			// If we've reached the lastest node and it was inserted successfully,
			// then we need to add an extra node.
			// The extra node will be the `id` node.
			idNode, err := GetNodeByType("id", nil)
			idNode.Parent = tmpNode
			tmpNode.Children = idNode

			return idNode, true, err
		}

		// Otherwise there still are more levels
		return insertRule(tmpNode, lvl+1, keys, rule)
	}

	// Otherwise, a jump needs to be done.
	if current.Value.GetKey() == keys[len(keys)-1] {
		// This scenario happens when the child node is the last node in the
		// level of nodes
		return current.Children, true, nil
	}

	// Finally, just jump to the next node in the branch
	return insertRule(current, lvl+1, keys, rule)

}

// LookupID search through the Decision tree for a Yara rule that matches with
// the packet metadata
func LookupID(pkt types.MetaRule) (id string, err error) {
	// The Decision tree must be initialized before procced
	if Decision == nil || Decision.Children == nil {
		return "", ErrDecisionTreeNotInit
	}

	// Initiate a backtracking search the the target
	bt := NewBactracking(pkt)

	// Start the search omitting the root node as it is only an empty node
	bt.Backtrack(Decision.Children)

	// If finally there is a solution, just returned it
	logger.Log.Debugf("<<< Got solution: %t", bt.HasSolution())
	if bt.HasSolution() {

		return bt.GetResult(), nil
	}

	// Otherwise, rise an error
	return "", ErrSolutionNotFound
}
