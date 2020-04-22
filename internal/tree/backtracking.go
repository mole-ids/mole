package tree

import (
	"github.com/jpalanco/mole/internal/types"
)

// Bactracking implements the backtracking search
type Bactracking struct {
	target   types.MetaRule
	solution types.MetaRule
	idNode   *Tree
}

// NewBactracking retuns a new Backtracking object. The argument is the target
// to search for
func NewBactracking(target types.MetaRule) *Bactracking {
	return &Bactracking{
		target:   target,
		solution: make(types.MetaRule),
	}
}

// GetResult returns the result
func (bt *Bactracking) GetResult() string {
	return bt.idNode.Value.GetValue()
}

// HasSolution returns true if there is a solution so far, otherwise it returns
// false
func (bt *Bactracking) HasSolution() bool {
	if len(bt.target) == len(bt.solution) {
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
	bt.solution[node.GetKey()] = node
}

// Accepted check whether the NodeValue is a good candidate for the solution
func (bt *Bactracking) Accepted(node types.NodeValue) bool {
	return node.Match(bt.target[node.GetKey()])
}

// Backtrack performs the search
func (bt *Bactracking) Backtrack(node *Tree) *Tree {
	if bt.Accepted(node.Value) {
		bt.AddPartial(node.Value)
		if bt.HasSolution() {
			bt.idNode = node.Children
			return bt.idNode
		}
		return bt.Backtrack(node.Children)
	}

	var current *Tree
	child := node.Next
	for child != nil {
		current = child
		child = current.Next
		if res := bt.Backtrack(current); res != nil {
			return res
		}
	}
	return nil
}
