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

// NodeType defines the node type
type NodeType string

// NodeValue is the interface that all nodes in the decision tree needs to meet
type NodeValue interface {
	Match(NodeValue) bool
	MatchB(NodeValue) bool
	GetKey() string
	GetValue() string
}

const (
	// Root defines the root node keyword
	Root NodeType = "root"
	// Proto defines the protocol node keyword
	Proto NodeType = "proto"
	// SrcNet defines the source IP node keyword
	SrcNet NodeType = "src"
	// SrcPort defines the source port node keyword
	SrcPort NodeType = "sport"
	// DstNet defines the destination IP node keyword
	DstNet NodeType = "dst"
	// DstPort defines the destination port node keyword
	DstPort NodeType = "dport"
	// ID defines the id node keyword
	ID NodeType = "id"
)

var (
	// NodeTypeLookUp utility to lookup node types based on its keywords
	NodeTypeLookUp = map[string]NodeType{
		"root":  Root,
		"proto": Proto,
		"src":   SrcNet,
		"sport": SrcPort,
		"dst":   DstNet,
		"dport": DstPort,
		"id":    ID,
	}
)

func (nt NodeType) String() string {
	return string(nt)
}

const (
	minPort      = "0"
	minPortInt   = 0
	maxPort      = "65535"
	maxPortInt   = 65535
	notOp        = "!"
	maskSplitter = "/"
	ipMask       = "/32"
)

var (
	// Keywords defines what Yara metadata entries are used for processing the rule.
	// This array also defines the order in which each key is taking into account
	Keywords = []string{"proto", "src", "sport", "dst", "dport"}

	// RuleDefVersion defines the version of the metadata accepted by Mole
	// this will be handy to version rules later on
	RuleDefVersion = "1.0"

	// RangeSplitter character used to define a range, like ports 80:443
	RangeSplitter = ":"
	// SequenceSplitter character used to define a sequence, like ports 80,443
	SequenceSplitter = ","
)

// GetNodeValue returns the NodeValue based on the key value
func GetNodeValue(key string, value interface{}) (NodeValue, error) {
	switch key {
	case Proto.String():
		node, err := NewProto(value)
		if err != nil {
			return nil, err
		}
		return node, err
	case SrcNet.String():
		node, err := NewSrcNet(value)
		if err != nil {
			return nil, err
		}
		return node, err
	case SrcPort.String():
		node, err := NewSrcPort(value)
		if err != nil {
			return nil, err
		}
		return node, err
	case DstNet.String():
		node, err := NewDstNet(value)
		if err != nil {
			return nil, err
		}
		return node, err
	case DstPort.String():
		node, err := NewDstPort(value)
		if err != nil {
			return nil, err
		}
		return node, err
	case ID.String():
		node := NewID()
		return node, nil
	}
	return nil, ErrUndefinedNode
}
