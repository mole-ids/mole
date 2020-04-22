package types

import (
	"math/rand"
	"net"
	"strings"
	"time"

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
// acomplish the NodeValue interface
func (mr MRRoot) Match(proto NodeValue) bool {
	return true
}

// GetKey is a dummy function that needs to be implemented in terms to
// acomplish the NodeValue interface
func (mr MRRoot) GetKey() string {
	return mr.Key
}

// GetValue is a dummy function that needs to be implemented in terms to
// acomplish the NodeValue interface
func (mr MRRoot) GetValue() string {
	return mr.Value
}

// MRType represents Type node
type MRType struct {
	Key   string
	Value string
}

// NewMRType returns a new type node
func NewMRType(value interface{}) (MRType, error) {
	var err error
	sValue, ok := value.(string)
	if !ok {
		err = errors.New("creating type node: value is not a type of string")
	}
	return MRType{
		Key:   "type",
		Value: sValue,
	}, err
}

// Match checks whether the argument's value match with the node value
func (mr MRType) Match(typ NodeValue) bool {
	return mr.Value == typ.GetValue()
}

// GetKey returns the key associated to the node which is also part of the keywords
func (mr MRType) GetKey() string {
	return mr.Key
}

// GetValue returns a string version of the node value
func (mr MRType) GetValue() string {
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
	Key   string
	Value string
}

// NewSRCMRPort returns a new MRPort node with `src_port` as key
func NewSRCMRPort(value interface{}) (MRPort, error) {
	return newMRPort("src_port", value)
}

// NewDSTMRPort returns a new MRPort node with `dst_port` as key
func NewDSTMRPort(value interface{}) (MRPort, error) {
	return newMRPort("dst_port", value)
}

func newMRPort(key string, value interface{}) (MRPort, error) {
	var err error
	sValue, ok := value.(string)
	if !ok {
		err = errors.New("creating port nodo: value is not a type of string")
	}
	return MRPort{
		Key:   key,
		Value: sValue,
	}, err
}

// Match checks whether the argument's value match with the node value
func (mr MRPort) Match(port NodeValue) bool {
	if strings.Contains(mr.Value, RangeSplit) {
		ports := strings.Split(mr.Value, RangeSplit)
		portValue := port.GetValue()
		if portValue >= ports[0] && portValue <= ports[1] {
			return true
		}
	}

	return mr.Value == port.GetValue()
}

// GetKey returns the key associated to the node which is also part of the keywords
func (mr MRPort) GetKey() string {
	return mr.Key
}

// GetValue returns a string version of the node value
func (mr MRPort) GetValue() string {
	return mr.Value
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
	case "type":
		node, err := NewMRType(value)
		if err != nil {
			return nil, err
		}
		return node, err
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
