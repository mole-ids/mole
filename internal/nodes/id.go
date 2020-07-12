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

import (
	"math/rand"
	"time"

	"github.com/oklog/ulid"
)

// NodeID represents proto node
type NodeID struct {
	key   string
	value ulid.ULID
}

// NewID returns a new NodeID node
func NewID() NodeID {
	t := time.Now()
	entropy := ulid.Monotonic(rand.New(rand.NewSource(t.UnixNano())), 0)
	return NodeID{
		key:   ID.String(),
		value: ulid.MustNew(ulid.Timestamp(t), entropy),
	}
}

// Match checks whether the argument's value match with the node value
func (nid NodeID) Match(id NodeValue) bool {
	return nid.value.String() == id.GetValue()
}

// MatchB checks whether the argument's value match with the node value
func (nid NodeID) MatchB(id NodeValue) bool {
	return nid.value.String() == id.GetValue()
}

// GetKey returns the key associated to the node which is also part of the keywords
func (nid NodeID) GetKey() string {
	return nid.key
}

// GetValue returns a string version of the node value
func (nid NodeID) GetValue() string {
	return nid.value.String()
}
