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

import "strings"

// NodeProto represents proto node
type NodeProto struct {
	key      string
	value    string
	original string
	not      bool
}

// NewProto returns a new proto node
func NewProto(value interface{}) (NodeProto, error) {
	var err error
	sValue, ok := value.(string)
	if !ok {
		err = ErrConversionType
	}

	var original string = sValue
	var not bool = false

	if strings.HasPrefix(sValue, notOp) {
		not = true
		sValue = strings.Replace(sValue, notOp, "", -1)
	}
	return NodeProto{
		key:      Proto.String(),
		value:    sValue,
		original: original,
		not:      not,
	}, err
}

// Match checks whether the argument's value match with the node value
func (np NodeProto) Match(proto NodeValue) bool {
	return np.MatchB(proto)
}

func (np NodeProto) match(proto NodeValue) bool {
	return np.value == proto.GetValue()
}

// MatchB checks whether the argument's value match with the node value
func (np NodeProto) MatchB(proto NodeValue) bool {
	vProto, ok := proto.(NodeProto)
	if !ok {
		return false
	}

	not := vProto.HasNot()

	if np.not {
		if not {
			return np.match(proto)
		}
		return !np.match(proto)
	}
	if not {
		return !np.match(proto)
	}
	return np.match(proto)
}

// GetKey returns the key associated to the node which is also part of the keywords
func (np NodeProto) GetKey() string {
	return np.key
}

// GetValue returns a string version of the node value
func (np NodeProto) GetValue() string {
	return np.value
}

// GetOriginal returns a string version of the node value without parsing
func (np NodeProto) GetOriginal() string {
	return np.original
}

// HasNot returns whether the node has not operator
func (np NodeProto) HasNot() bool {
	return np.not
}
