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
package nodes

// NodeRoot represents the root node
type NodeRoot struct {
	key   string
	value string
}

// NewRoot returns a new NodeRoot node
func NewRoot() NodeRoot {
	return NodeRoot{
		key:   Root.String(),
		value: "",
	}
}

// Match is a dummy function that needs to be implemented in terms to
// accomplish the NodeValue interface
func (nr NodeRoot) Match(proto NodeValue) bool {
	return true
}

// MatchB is a dummy function that needs to be implemented in terms to
// accomplish the NodeValue interface
func (nr NodeRoot) MatchB(proto NodeValue) bool {
	return true
}

// GetKey is a dummy function that needs to be implemented in terms to
// accomplish the NodeValue interface
func (nr NodeRoot) GetKey() string {
	return nr.key
}

// GetValue is a dummy function that needs to be implemented in terms to
// accomplish the NodeValue interface
func (nr NodeRoot) GetValue() string {
	return nr.value
}
