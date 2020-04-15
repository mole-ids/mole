package tree

import (
	"fmt"

	"github.com/hillu/go-yara"
	"github.com/pkg/errors"

	"github.com/jpalanco/mole/pkg/rules"
)

type Tree struct {
	Value    rules.NodeValue
	Parent   *Tree
	Next     *Tree
	Children *Tree
}

type RuleMap map[string][]yara.Rule

var (
	Decicion *Tree
)

func TreeFromRules(rulesList []yara.Rule) (rmap RuleMap, err error) {
	rmap = make(RuleMap)

	Decicion = New(rules.NewMRRoot())

	for _, rule := range rulesList {
		meta, err := rules.GetRuleMetaInfo(rule)
		if err != nil {
			return nil, errors.Errorf("unable to get metadata from rule %s", rule.Identifier())
		}
		idNode, _, err := InsertRule(Decicion, 0, rules.Keywords, meta)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to insert rule %s", rule.Identifier())
		}

		id := idNode.Value.GetValue()
		rmap[id] = append(rmap[id], rule)
	}
	return
}

func New(value rules.NodeValue) *Tree {
	nValue, ok := value.(rules.NodeValue)
	if !ok {
		fmt.Printf("Wrong type: %v\n", value)
	}
	return &Tree{
		Value:    nValue,
		Parent:   nil,
		Next:     nil,
		Children: nil,
	}
}

func getNodeByType(key string, value interface{}) (*Tree, error) {
	switch key {
	case "type":
		node, err := rules.NewMRAlert(value)
		if err != nil {
			return nil, err
		}
		return New(node), err
	case "proto":
		node, err := rules.NewMRProto(value)
		if err != nil {
			return nil, err
		}
		return New(node), err
	case "src":
		node, err := rules.NewSRCMRAddress(value)
		if err != nil {
			return nil, err
		}
		return New(node), err
	case "src_port":
		node, err := rules.NewSRCMRPort(value)
		if err != nil {
			return nil, err
		}
		return New(node), err
	case "dst":
		node, err := rules.NewDSTMRAddress(value)
		if err != nil {
			return nil, err
		}
		return New(node), err
	case "dst_port":
		node, err := rules.NewDSTMRPort(value)
		if err != nil {
			return nil, err
		}
		return New(node), err
	case "id":
		node, err := rules.NewMRid()
		return New(node), err
	}
	return nil, errors.Errorf("Node type %s not recognized", key)
}

func IsRoot(tree *Tree) bool {
	return tree != nil && tree.Parent == nil && tree.Next == nil
}

func InsertRule(tree *Tree, lvl int, keys []string, rule rules.MetaRule) (nodeID *Tree, ok bool, err error) {
	if tree.Children == nil {
		// This happens when a new branch is being built up

		if lvl < len(keys) {
			// Getting a new node. The new node will be the new children node
			node, err := getNodeByType(keys[lvl], rule[keys[lvl]])
			if err != nil {
				return nil, false, errors.Wrapf(err, "when creating node at level %d with key %s", lvl, keys[lvl])
			}

			// Setting up the node with pointers
			node.Parent = tree
			tree.Children = node

			// if level hasn't reached the max value, keep inserting nodes
			return InsertRule(node, lvl+1, keys, rule)
		} else {
			// If we've reached the lastest node and it was inserted successfully,
			// then we need to add an extra node.
			// The extra node will be the `id` node.
			idNode, err := getNodeByType("id", nil)
			idNode.Parent = tree
			tree.Children = idNode

			return idNode, true, err
		}
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
	tmpNode, err := getNodeByType(keys[lvl], rule[keys[lvl]])
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
			idNode, err := getNodeByType("id", nil)
			idNode.Parent = tmpNode
			tmpNode.Children = idNode

			return idNode, true, err
		}

		// Otherwise there still are more levels
		return InsertRule(tmpNode, lvl+1, keys, rule)
	}

	// Otherwise, a jump needs to be done.
	if current.Value.GetKey() == keys[len(keys)-1] {
		// This scenario happens when the child node is the last node in the
		// level of nodes
		return current.Children, true, nil
	}

	// Finally, just jump to the next node in the branch
	return InsertRule(current, lvl+1, keys, rule)

}
