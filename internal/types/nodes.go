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

// NodeRoot returns a new MRRoot node
func NodeRoot() MRRoot {
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

// NodeProto returns a new MRProto node
func NodeProto(value interface{}) (MRProto, error) {
	var err error
	sValue, ok := value.(string)
	if !ok {
		err = ErrConversionType
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
	Key      string
	Value    *net.IPNet
	List     bool
	NetList  []*net.IPNet
	Not      bool
	Original string
}

// NodeSrcAddress returns a new MRAddress node with `src` as key
func NodeSrcAddress(value interface{}) (MRAddress, error) {
	return nodeAddress("src", value)
}

// NodeDstAddress returns a new MRAddress node with `dst` as key
func NodeDstAddress(value interface{}) (MRAddress, error) {
	return nodeAddress("dst", value)
}

func nodeAddress(key string, value interface{}) (ipnet MRAddress, err error) {
	sValue, ok := value.(string)
	if !ok {
		return ipnet, ErrConversionType
	}

	var netv4 *net.IPNet
	var netList []*net.IPNet
	var lst bool
	var original string = sValue
	var not bool = false

	if strings.HasPrefix(sValue, "!") {
		not = true
		sValue = strings.Replace(sValue, "!", "", -1)
	}

	if strings.Contains(sValue, SequenceSplitter) {
		lst = true
		nets := strings.Split(sValue, SequenceSplitter)

		for _, n := range nets {
			if !strings.Contains(n, "/") {
				n = n + "/32"
			}

			_, nv4, err := net.ParseCIDR(n)
			if err != nil {
				return ipnet, errors.Wrap(err, WhileParsingCIDRMsg)
			}

			netList = append(netList, nv4)
		}
	} else {
		if !strings.Contains(sValue, "/") {
			sValue = sValue + "/32"
		}

		_, netv4, err = net.ParseCIDR(sValue)
		if err != nil {
			return ipnet, errors.Wrap(err, WhileParsingCIDRMsg)
		}
	}

	ipnet = MRAddress{
		Key:      key,
		Value:    netv4,
		List:     lst,
		NetList:  netList,
		Not:      not,
		Original: original,
	}

	return ipnet, err
}

// IsList returns whether the node is a list of address or not
func (mr MRAddress) IsList() bool {
	return mr.List
}

// GetList returns the list of address if any or a empty list
func (mr MRAddress) GetList() []*net.IPNet {
	if mr.List {
		return mr.NetList
	}
	return []*net.IPNet{}
}

// Match checks whether the argument's value match with the node value
func (mr MRAddress) Match(addr NodeValue) bool {
	if mr.Not {
		return !mr.match(addr)
	}
	return mr.match(addr)
}

func (mr MRAddress) match(addr NodeValue) bool {
	vAddr, ok := addr.(MRAddress)
	if !ok {
		return false
	}

	var result bool

	if mr.List && vAddr.IsList() {
		vAddrList := vAddr.GetList()

		for _, myAddr := range mr.NetList {
			for jdx, addre := range vAddrList {
				if ones, _ := myAddr.Mask.Size(); ones < 32 {
					result = myAddr.Contains(addre.IP)
				} else {
					result = myAddr.IP.Equal(addre.IP)
				}
				if result {
					vAddrList = append(vAddrList[:jdx], vAddrList[jdx+1:]...)
				}
			}

			if len(vAddrList) == 0 {
				// Avoid looping mr.NetList if vAddrList is over
				return true
			}
		}

		if len(vAddrList) == 0 {
			return true
		}

		return false

	} else if mr.List && !vAddr.IsList() {
		for _, myAddr := range mr.NetList {
			if ones, _ := myAddr.Mask.Size(); ones < 32 {
				result = myAddr.Contains(vAddr.Value.IP)
			} else {
				result = myAddr.IP.Equal(vAddr.Value.IP)
			}
			if result {
				return result
			}
		}
		return false
	} else if !mr.List && vAddr.IsList() {
		vAddrList := vAddr.GetList()

		if len(vAddrList) == 0 {
			return false
		}

		if ones, _ := mr.Value.Mask.Size(); ones == 32 {
			if len(vAddrList) > 1 {
				return false
			}
			return mr.Value.IP.Equal(vAddrList[0].IP)
		}

		for _, addre := range vAddrList {
			if res := mr.Value.Contains(addre.IP); !res {
				return false
			}
		}
		return true
	}
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
	return mr.Original
}

// MRPort represents proto node
type MRPort struct {
	Range    bool
	Low      int
	High     int
	List     bool
	PortList []int
	Not      bool
	Key      string
	Value    int
	Original string
}

// NodeSrcMRPort returns a new MRPort node with `sport` as key
func NodeSrcMRPort(value interface{}) (MRPort, error) {
	return nodePort("sport", value)
}

// NodeDstMRPort returns a new MRPort node with `dport` as key
func NodeDstMRPort(value interface{}) (MRPort, error) {
	return nodePort("dport", value)
}

func nodePort(key string, value interface{}) (mrport MRPort, err error) {
	sValue, ok := value.(string)
	if !ok {
		return mrport, ErrConversionType
	}

	var original string = sValue
	var rng, lst bool
	var ports [2]int
	var portList []int
	var iValue int
	var not bool = false

	if strings.HasPrefix(sValue, "!") {
		not = true
		sValue = strings.Replace(sValue, "!", "", -1)
	}

	if strings.Contains(sValue, RangeSplitter) {
		if strings.Contains(sValue, SequenceSplitter) {
			return mrport, ErrMixedFormats
		}

		if strings.Count(sValue, RangeSplitter) > 1 {
			return mrport, ErrRangeExceeded
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
			return mrport, errors.Errorf(InvalidPortNumberMsg, portsString[0])
		}
		ports[1], err = strconv.Atoi(portsString[1])
		if err != nil {
			return mrport, errors.Errorf(InvalidPortNumberMsg, portsString[1])
		}

		if ports[0] >= ports[1] {
			return mrport, ErrPortBoundsNotValid
		}

		rng = true
	} else if strings.Contains(sValue, SequenceSplitter) {
		if strings.Contains(sValue, RangeSplitter) {
			return mrport, ErrMixedFormats
		}

		for _, vs := range strings.Split(sValue, SequenceSplitter) {
			if vs != "" {
				v, err := strconv.Atoi(vs)
				if err != nil {
					return mrport, errors.Errorf(InvalidPortNumberMsg, vs)
				}
				portList = append(portList, v)
			}
		}
		sort.Ints(portList)
		lst = true
	} else {
		iValue, err = strconv.Atoi(sValue)
		if err != nil {
			return mrport, errors.Errorf(InvalidPortNumberMsg, sValue)
		}
	}

	mrport = MRPort{
		Range:    rng,
		Low:      ports[0],
		High:     ports[1],
		List:     lst,
		PortList: portList,
		Not:      not,
		Key:      key,
		Value:    iValue,
		Original: original,
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
	if mr.Not {
		return !mr.match(port)
	}
	return mr.match(port)
}

func (mr MRPort) match(port NodeValue) bool {
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

// Nodeid returns a new MRid node
func Nodeid() (MRid, error) {
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
		node, err := NodeProto(value)
		if err != nil {
			return nil, err
		}
		return node, err
	case "src":
		node, err := NodeSrcAddress(value)
		if err != nil {
			return nil, err
		}
		return node, err
	case "sport":
		node, err := NodeSrcMRPort(value)
		if err != nil {
			return nil, err
		}
		return node, err
	case "dst":
		node, err := NodeDstAddress(value)
		if err != nil {
			return nil, err
		}
		return node, err
	case "dport":
		node, err := NodeDstMRPort(value)
		if err != nil {
			return nil, err
		}
		return node, err
	case "id":
		node, err := Nodeid()
		return node, err
	}
	return nil, ErrUndefinedNode
}
