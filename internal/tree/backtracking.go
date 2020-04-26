package tree

import (
	"github.com/jpalanco/mole/internal/types"
)

// Bactracking implements the backtracking search
type Bactracking struct {
	// target this is the data mole is looking for. In other words, this value
	// is the one that cames from the captured packet
	target types.MetaRule
	// solution is the solution that backtraking will be building while traversing
	// the tree
	solution types.MetaRule
	// idNode is the last node, the one with the identifier
	idNode *Tree
}

// NewBactracking retuns a new Backtracking object. The argument is the target
// to search for
func NewBactracking(target types.MetaRule) *Bactracking {
	return &Bactracking{
		target:   target,
		solution: make(types.MetaRule),
	}
}

// GetResult returns the identifier from the `id` node
func (bt *Bactracking) GetResult() string {
	return bt.idNode.Value.GetValue()
}

// HasSolution returns true if there is a solution so far, otherwise it returns
// false
func (bt *Bactracking) HasSolution() bool {
	if len(bt.target) == len(bt.solution) {
		// As target and solution are both maps, a solution is as easy as checking
		// every key's value
		for k, v := range bt.target {
			if !bt.solution[k].Match(v) {
				return false
			}
		}
		return true
	}
	return false
}

// AddPartial adds partial solution using the NodeValue
func (bt *Bactracking) AddPartial(node types.NodeValue) {
	// Adds the node as a potential solution
	bt.solution[node.GetKey()] = node
}

// Accepted check whether the NodeValue is a good candidate for the solution
func (bt *Bactracking) Accepted(node types.NodeValue) bool {
	// Validates whether `node` match with the one in the target map
	return node.Match(bt.target[node.GetKey()])
}

// Backtrack performs the search
func (bt *Bactracking) Backtrack(node *Tree) *Tree {
	// If `node` is accepted
	if bt.Accepted(node.Value) {
		// Add it as partial solution
		bt.AddPartial(node.Value)
		// If there is a solution, just grab it
		if bt.HasSolution() {
			bt.idNode = node.Children
			return bt.idNode
		}
		// Otherwise, as we are in the right way go deeper in the tree
		return bt.Backtrack(node.Children)
	}

	// If `node` was not elected, then visit next nodes in the same level
	var current *Tree
	child := node.Next
	for child != nil {
		current = child
		child = current.Next
		// For each next node do backtrack
		if res := bt.Backtrack(current); res != nil {
			return res
		}
	}
	return nil
}
