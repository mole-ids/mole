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
	"github.com/mole-ids/mole/internal/nodes"
	"github.com/mole-ids/mole/internal/types"
	"github.com/mole-ids/mole/pkg/logger"
)

// Bactracking implements the backtracking search
type Bactracking struct {
	// target this is the data mole is looking for. In other words, this value
	// is the one that cames from the captured packet
	target types.MetaRule
	// partialSolution is the solution that backtraking will be building while traversing
	// the tree
	partialSolution types.MetaRule
	solution        bool
	// idNodes is the last node, the one with the identifier
	idNodes []*Tree
}

// NewBactracking returns a new Backtracking object. The argument is the target
// to search for
func NewBactracking(target types.MetaRule) *Bactracking {
	logger.Log.Debugf(">>> Target: proto:%s src:%s sport:%s dst:%s dport:%s", target["proto"].GetValue(), target["src"].GetValue(), target["sport"].GetValue(), target["dst"].GetValue(), target["dport"].GetValue())
	return &Bactracking{
		target:          target,
		partialSolution: make(types.MetaRule),
		solution:        false,
	}
}

// GetResult returns the identifier from the `id` node
func (bt *Bactracking) GetResult() []string {
	var res []string
	for _, n := range bt.idNodes {
		res = append(res, n.Value.GetValue())
	}
	return res
}

// Solution returns whether the algorithm has a soluiton
func (bt *Bactracking) Solution() bool {
	return bt.solution
}

// hasSolution returns true if there is a solution so far, otherwise it returns
// false
func (bt *Bactracking) hasSolution() bool {
	if len(bt.target) == len(bt.partialSolution) {
		// As target and solution are both maps, a solution is as easy as checking
		// every key's value
		for k, v := range bt.target {
			if !bt.partialSolution[k].Match(v) {
				return false
			}
		}
		bt.solution = true
		return true
	}
	return false
}

// AddPartial adds partial solution using the NodeValue
func (bt *Bactracking) AddPartial(node nodes.NodeValue) {
	// Adds the node as a potential solution
	bt.partialSolution[node.GetKey()] = node
}

// Accepted check whether the NodeValue is a good candidate for the solution
func (bt *Bactracking) Accepted(node nodes.NodeValue) bool {
	match := node.Match(bt.target[node.GetKey()])
	// Validates whether `node` match with the one in the target map
	logger.Log.Debugf("Checking (%s): %s == %s => %t", node.GetKey(), node.GetValue(), bt.target[node.GetKey()].GetValue(), match)
	return match
}

func (bt *Bactracking) removePartialNode(node *Tree) {
	delete(bt.partialSolution, node.Value.GetKey())
}

// Backtrack performs the search
func (bt *Bactracking) Backtrack(node *Tree) {
	// If `node` is accepted
	if bt.Accepted(node.Value) {
		// Add it as partial solution
		bt.AddPartial(node.Value)
		// If there is a solution, just grab it
		if bt.hasSolution() {
			bt.idNodes = append(bt.idNodes, node.Children)
			return
		}

		// Otherwise, as we are in the right way go deeper in the tree
		bt.Backtrack(node.Children)
		bt.removePartialNode(node.Children)

		var current *Tree
		child := node.Children.Next
		for child != nil {
			current = child
			child = current.Next

			// For each next node do backtrack
			bt.Backtrack(current)
			bt.removePartialNode(current)
		}

		return
	}

	if node.Next != nil {
		var current *Tree
		child := node.Next
		for child != nil {
			current = child
			child = current.Next

			// For each next node do backtrack
			bt.Backtrack(current)
			bt.removePartialNode(current)
		}
	}

	return
}
