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
package types

import (
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mole-ids/mole/internal/utils"
	"github.com/oklog/ulid"
	"github.com/pkg/errors"
)

// MRRoot represents the root node
type MRRoot struct {
	Key   string
	Value string
}

// NewMRRoot returns a new MRRoot node
func NewMRRoot() MRRoot {
	return MRRoot{Key: "root"}
}

// Match is a dummy function that needs to be implemented in terms to
// accomplish the NodeValue interface
func (mr MRRoot) Match(proto NodeValue) bool {
	return true
}

// GetKey is a dummy function that needs to be implemented in terms to
// accomplish the NodeValue interface
func (mr MRRoot) GetKey() string {
	return mr.Key
}

// GetValue is a dummy function that needs to be implemented in terms to
// accomplish the NodeValue interface
func (mr MRRoot) GetValue() string {
	return mr.Value
}

// MRProto represents proto node
type MRProto struct {
	Key   string
	Value string
}

// NewMRProto returns a new MRProto node
func NewMRProto(value interface{}) (MRProto, error) {
	var err error
	sValue, ok := value.(string)
	if !ok {
		err = errors.New("creating proto node: value is not a type of string")
	}
	return MRProto{
		Key:   "proto",
		Value: sValue,
	}, err
}

// Match checks whether the argument's value match with the node value
func (mr MRProto) Match(proto NodeValue) bool {
	return mr.Value == proto.GetValue()
}

// GetKey returns the key associated to the node which is also part of the keywords
func (mr MRProto) GetKey() string {
	return mr.Key
}

// GetValue returns a string version of the node value
func (mr MRProto) GetValue() string {
	return mr.Value
}

// MRAddress represents proto node
type MRAddress struct {
	Key   string
	Value *net.IPNet
}

// NewSRCMRAddress returns a new MRAddress node with `src` as key
func NewSRCMRAddress(value interface{}) (MRAddress, error) {
	return newMRAddress("src", value)
}

// NewDSTMRAddress returns a new MRAddress node with `dst` as key
func NewDSTMRAddress(value interface{}) (MRAddress, error) {
	return newMRAddress("dst", value)
}

func newMRAddress(key string, value interface{}) (ipnet MRAddress, err error) {
	sValue, ok := value.(string)
	if !ok {
		return ipnet, errors.Errorf("creating address (%s) nodo: value is not a type of string", key)
	}
	var netv4 *net.IPNet
	if strings.Contains(sValue, "/") {
		_, netv4, err = net.ParseCIDR(sValue)
		if err != nil {
			return ipnet, err
		}
	} else {
		_, netv4, err = net.ParseCIDR(sValue + "/32")
		if err != nil {
			return ipnet, err
		}
	}

	ipnet = MRAddress{
		Key:   key,
		Value: netv4,
	}

	return ipnet, err
}

// Match checks whether the argument's value match with the node value
func (mr MRAddress) Match(addr NodeValue) bool {
	vAddr, ok := addr.(MRAddress)
	if !ok {
		return false
	}

	var result bool

	// If node is a net, we should check if the IP is inside that network
	if ones, _ := mr.Value.Mask.Size(); ones < 32 {
		result = mr.Value.Contains(vAddr.Value.IP)
	} else {
		result = mr.Value.IP.Equal(vAddr.Value.IP)
	}

	return result
}

// GetKey returns the key associated to the node which is also part of the keywords
func (mr MRAddress) GetKey() string {
	return mr.Key
}

// GetValue returns a string version of the node value
func (mr MRAddress) GetValue() string {
	return mr.Value.String()
}

// MRPort represents proto node
type MRPort struct {
	Range    bool
	Low      int
	High     int
	List     bool
	PortList []int
	Key      string
	Value    int
	Original string
}

// NewSRCMRPort returns a new MRPort node with `src_port` as key
func NewSRCMRPort(value interface{}) (MRPort, error) {
	return newMRPort("src_port", value)
}

// NewDSTMRPort returns a new MRPort node with `dst_port` as key
func NewDSTMRPort(value interface{}) (MRPort, error) {
	return newMRPort("dst_port", value)
}

func newMRPort(key string, value interface{}) (mrport MRPort, err error) {
	sValue, ok := value.(string)
	if !ok {
		return mrport, errors.New("creating port nodo: value is not a type of string")
	}

	var rng, lst bool
	var ports [2]int
	var portList []int
	var iValue int
	if strings.Contains(sValue, RangeSplitter) {
		if strings.Contains(sValue, SequenceSplitter) {
			return mrport, errors.New("mixed range types are not allowed")
		}

		if strings.Count(sValue, RangeSplitter) > 1 {
			return mrport, errors.New("port range can not contain more than one range splitter")
		}

		portsString := strings.Split(sValue, RangeSplitter)

		if portsString[0] == "" {
			portsString[0] = "0"
		}

		if portsString[1] == "" {
			portsString[1] = "65535"
		}

		ports[0], err = strconv.Atoi(portsString[0])
		if err != nil {
			return mrport, errors.Errorf("value %s is not valid port number", portsString[0])
		}
		ports[1], err = strconv.Atoi(portsString[1])
		if err != nil {
			return mrport, errors.Errorf("value %s is not valid port number", portsString[1])
		}

		if ports[0] >= ports[1] {
			return mrport, errors.New("lower port cannot be higher or equal to the higher port in port range")
		}

		rng = true
	} else if strings.Contains(sValue, SequenceSplitter) {
		if strings.Contains(sValue, RangeSplitter) {
			return mrport, errors.New("mixed range types are not allowed")
		}

		for _, vs := range strings.Split(sValue, SequenceSplitter) {
			if vs != "" {
				v, err := strconv.Atoi(vs)
				if err != nil {
					return mrport, errors.Errorf("value %s is not valid port number", vs)
				}
				portList = append(portList, v)
			}
		}
		sort.Ints(portList)
		lst = true
	} else {
		iValue, err = strconv.Atoi(sValue)
		if err != nil {
			return mrport, errors.Errorf("value %s is not valid port number", sValue)
		}
	}

	mrport = MRPort{
		Range:    rng,
		Low:      ports[0],
		High:     ports[1],
		List:     lst,
		PortList: portList,
		Key:      key,
		Value:    iValue,
		Original: sValue,
	}

	return mrport, err
}

// IsList returns the port range
func (mr MRPort) IsList() bool {
	return mr.List
}

// GetList returns the list values
func (mr MRPort) GetList() []int {
	if mr.List {
		return mr.PortList
	}
	return []int{}
}

// IsRange returns the port range
func (mr MRPort) IsRange() bool {
	return mr.Range
}

// GetRange returns the port range
func (mr MRPort) GetRange() (int, int) {
	if mr.Range {
		return mr.Low, mr.High
	}
	return -1, -1
}

// Match checks whether the argument's value match with the node value
func (mr MRPort) Match(port NodeValue) bool {
	vPort := port.(MRPort)

	if vPort.IsRange() {
		low, high := vPort.GetRange()

		if mr.Range {
			if low >= mr.Low && high <= mr.High {
				return true
			}

			return false
		}

		if mr.List {
			for p := low; p <= high; p++ {
				if !utils.InInts(p, mr.PortList) {
					return false
				}
			}
			return true
		}

		return mr.Value >= low && mr.Value <= high

	} else if vPort.IsList() {
		list := vPort.GetList()

		if mr.Range {
			for _, p := range list {
				if p < mr.Low && p > mr.High {
					return false
				}
			}
			return true
		}

		if mr.List {
			sort.Ints(list)

			for _, p := range list {
				if !utils.InInts(p, mr.PortList) {
					return false
				}
			}
			return true
		}

		for _, p := range list {
			if p == mr.Value {
				return true
			}
		}
		return false
	}

	v, _ := strconv.Atoi(vPort.GetValue())

	if mr.Range {
		return v >= mr.Low && v <= mr.High

	} else if mr.IsList() {
		for _, p := range mr.PortList {
			if p == v {
				return true
			}
		}
		return false
	}

	return mr.Value == v
}

// GetKey returns the key associated to the node which is also part of the keywords
func (mr MRPort) GetKey() string {
	return mr.Key
}

// GetValue returns a string version of the node value
func (mr MRPort) GetValue() string {
	return mr.Original
}

// MRid represents proto node
type MRid struct {
	Key   string
	Value ulid.ULID
}

// NewMRid returns a new MRid node
func NewMRid() (MRid, error) {
	t := time.Now()
	entropy := ulid.Monotonic(rand.New(rand.NewSource(t.UnixNano())), 0)
	return MRid{
		Key:   "id",
		Value: ulid.MustNew(ulid.Timestamp(t), entropy),
	}, nil
}

// Match checks whether the argument's value match with the node value
func (mr MRid) Match(id NodeValue) bool {
	return mr.Value.String() == id.GetValue()
}

// GetKey returns the key associated to the node which is also part of the keywords
func (mr MRid) GetKey() string {
	return mr.Key
}

// GetValue returns a string version of the node value
func (mr MRid) GetValue() string {
	return mr.Value.String()
}

// GetNodeValue returns the NodeValue based on the key value
func GetNodeValue(key string, value interface{}) (NodeValue, error) {
	switch key {
	case "proto":
		node, err := NewMRProto(value)
		if err != nil {
			return nil, err
		}
		return node, err
	case "src":
		node, err := NewSRCMRAddress(value)
		if err != nil {
			return nil, err
		}
		return node, err
	case "src_port":
		node, err := NewSRCMRPort(value)
		if err != nil {
			return nil, err
		}
		return node, err
	case "dst":
		node, err := NewDSTMRAddress(value)
		if err != nil {
			return nil, err
		}
		return node, err
	case "dst_port":
		node, err := NewDSTMRPort(value)
		if err != nil {
			return nil, err
		}
		return node, err
	case "id":
		node, err := NewMRid()
		return node, err
	}
	return nil, errors.Errorf("Node type %s not recognized", key)
}
