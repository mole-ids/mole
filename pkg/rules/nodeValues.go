package rules

import (
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/oklog/ulid"
	"github.com/pkg/errors"
)

type NodeValue interface {
	Match(NodeValue) bool
	GetKey() string
	GetValue() string
	SetValue(interface{}) error
}

// MetaRule defines yara rule metadata
type MetaRule map[string]string

// MRAlert represents nodes of type type
type MRRoot struct {
	Key   string
	Value string
}

func NewMRRoot() MRRoot {
	return MRRoot{}
}

func (mr MRRoot) Match(proto NodeValue) bool {
	return true
}

func (mr MRRoot) GetKey() string {
	return mr.Key
}
func (mr MRRoot) GetValue() string {
	return mr.Value
}

func (mr MRRoot) SetValue(value interface{}) (err error) {
	return nil
}

// MRAlert represents nodes of type type
type MRAlert struct {
	Key   string
	Value string
}

func NewMRAlert(value interface{}) (MRAlert, error) {
	var err error
	sValue, ok := value.(string)
	if !ok {
		err = errors.New("creating alert node: value is not a type of string")
	}
	return MRAlert{
		Key:   "alert",
		Value: sValue,
	}, err
}

func (mr MRAlert) Match(proto NodeValue) bool {
	return mr.Value == proto.GetValue()
}

func (mr MRAlert) GetKey() string {
	return mr.Key
}
func (mr MRAlert) GetValue() string {
	return mr.Value
}

func (mr MRAlert) SetValue(value interface{}) (err error) {
	sValue, ok := value.(string)
	if !ok {
		err = errors.New("setting value for alert node: value is not a type of string")
	}

	mr.Value = sValue
	return nil
}

// MRProto represents nodes of type protocol
type MRProto struct {
	Key   string
	Value string
}

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

func (mr MRProto) Match(proto NodeValue) bool {
	return mr.Value == proto.GetValue()
}

func (mr MRProto) GetKey() string {
	return mr.Key
}
func (mr MRProto) GetValue() string {
	return mr.Value
}

func (mr MRProto) SetValue(value interface{}) (err error) {
	sValue, ok := value.(string)
	if !ok {
		err = errors.New("setting value for proto node: value is not a type of string")
	}

	mr.Value = sValue
	return nil
}

// MRAddress represents nodes of type address or network
type MRAddress struct {
	Key   string
	Value *net.IPNet
}

func NewSRCMRAddress(value interface{}) (MRAddress, error) {
	return newMRAddress("src", value)
}

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

func (mr MRAddress) Match(addr NodeValue) bool {
	vAddr, ok := addr.(MRAddress)
	if !ok {
		return false
	}

	sameIP := mr.Value.IP.Equal(vAddr.Value.IP)

	return sameIP
}

func (mr MRAddress) GetKey() string {
	return mr.Key
}
func (mr MRAddress) GetValue() string {
	return mr.Value.String()
}

func (mr MRAddress) SetValue(value interface{}) (err error) {
	sValue, ok := value.(string)
	if !ok {
		return errors.Errorf("setting value for address (%s) nodo: value is not a type of string", mr.Key)
	}
	var netv4 *net.IPNet
	if strings.Contains(sValue, "/") {
		_, netv4, err = net.ParseCIDR(sValue)
		if err != nil {
			return errors.Wrap(err, "unable to parse CIDR")
		}
	} else {
		_, netv4, err = net.ParseCIDR(sValue + "/32")
		if err != nil {
			return errors.Wrap(err, "unable to parse CIDR")
		}
	}
	mr.Value = netv4
	return nil
}

// MRPort represents port and port ranges
type MRPort struct {
	Key   string
	Value string
}

func NewSRCMRPort(value interface{}) (MRPort, error) {
	return newMRPort("src_port", value)
}

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

func (mr MRPort) Match(port NodeValue) bool {
	return mr.Value == port.GetValue()
}

func (mr MRPort) GetKey() string {
	return mr.Key
}
func (mr MRPort) GetValue() string {
	return mr.Value
}

func (mr MRPort) SetValue(value interface{}) (err error) {
	sValue, ok := value.(string)
	if !ok {
		err = errors.New("setting value for port node: value is not a type of string")
	}

	mr.Value = sValue
	return nil
}

// MRAlert represents nodes of type type
type MRid struct {
	Key   string
	Value ulid.ULID
}

func NewMRid() (MRid, error) {
	t := time.Now()
	entropy := ulid.Monotonic(rand.New(rand.NewSource(t.UnixNano())), 0)
	return MRid{
		Key:   "id",
		Value: ulid.MustNew(ulid.Timestamp(t), entropy),
	}, nil
}

func (mr MRid) Match(id NodeValue) bool {
	return mr.Value.String() == id.GetValue()
}

func (mr MRid) GetKey() string {
	return mr.Key
}
func (mr MRid) GetValue() string {
	return mr.Value.String()
}

func (mr MRid) SetValue(value interface{}) (err error) {
	sValue, ok := value.(string)
	if !ok {
		err = errors.New("setting value for id node: value is not a type of string")
	}

	mr.Value, err = ulid.Parse(sValue)
	if err != nil {
		return errors.Wrap(err, "setting value for id node")
	}
	return nil
}
