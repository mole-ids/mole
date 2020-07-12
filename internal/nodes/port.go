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
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/mole-ids/mole/internal/utils"
	"github.com/mole-ids/mole/pkg/logger"
	"github.com/pkg/errors"
)

var (
	portValueRe = regexp.MustCompile(`^!?(:\d{1,4}|\d{1,4}(:(\d{1,4}|)|(,\d{1,4})*)?)`)
)

// NodePort represents port node
type NodePort struct {
	key       string
	portRange bool
	low       int
	high      int
	list      []int
	listS     []string
	not       bool
	original  string
}

// NewSrcPort returns a new NodePort node with `sport` as key
func NewSrcPort(value interface{}) (NodePort, error) {
	return nodePort(SrcPort.String(), value)
}

// NewDstPort returns a new NodePort node with `dport` as key
func NewDstPort(value interface{}) (NodePort, error) {
	return nodePort(DstPort.String(), value)
}

// nodePort should parse the input according to
func nodePort(key string, value interface{}) (nPort NodePort, err error) {
	sValue, ok := value.(string)
	if !ok {
		return nPort, ErrConversionType
	}

	if reValue := portValueRe.FindString(sValue); len(reValue) > 0 {
		sValue = reValue
	} else {
		return nPort, ErrInputDataNotValid
	}

	var original string = sValue
	var rng bool = false
	var ports [2]int
	var portList []int
	var listS []string
	var not bool = false

	if strings.HasPrefix(sValue, notOp) {
		not = true
		sValue = strings.Replace(sValue, notOp, "", -1)
	}

	if strings.Contains(sValue, RangeSplitter) {
		portsString := strings.Split(sValue, RangeSplitter)

		if portsString[0] == "" {
			portsString[0] = minPort
		}

		if portsString[1] == "" {
			portsString[1] = maxPort
		}

		ports[0], err = strconv.Atoi(portsString[0])
		if err != nil {
			// This will never happend as regexp won't allow it, but leave it as
			// protection
			return nPort, errors.Errorf(InvalidPortNumberMsg, portsString[0])
		}
		ports[1], err = strconv.Atoi(portsString[1])
		if err != nil {
			// This will never happend as regexp won't allow it, but leave it as
			// protection
			return nPort, errors.Errorf(InvalidPortNumberMsg, portsString[1])
		}

		if ports[0] >= ports[1] {
			return nPort, ErrPortBoundsNotValid
		}

		rng = true
	} else {
		for _, vs := range strings.Split(sValue, SequenceSplitter) {
			if vs != "" {
				v, err := strconv.Atoi(vs)
				if err != nil {
					// This will never happend as regexp won't allow it, but leave it as
					// protection
					return nPort, errors.Errorf(InvalidPortNumberMsg, vs)
				}
				portList = append(portList, v)
				listS = append(listS, vs)
			}
		}

		sort.Ints(portList)
	}

	nPort = NodePort{
		portRange: rng,
		low:       ports[0],
		high:      ports[1],
		list:      portList,
		listS:     listS,
		not:       not,
		key:       key,
		original:  original,
	}

	return nPort, nil
}

// IsRange returns the port range
func (np NodePort) IsRange() bool {
	return np.portRange
}

// GetList returns the list values
func (np NodePort) GetList() []int {
	return np.list
}

// GetRange returns the port range
func (np NodePort) GetRange() (int, int) {
	if np.portRange {
		return np.low, np.high
	}
	return -1, -1
}

// HasNot returns whether the node has not operator
func (np NodePort) HasNot() bool {
	return np.not
}

// Match checks whether the argument's value match with the node value
func (np NodePort) Match(port NodeValue) bool {
	vPort, ok := port.(NodePort)
	if !ok {
		if logger.Log != nil {
			logger.Log.Warn(ConversionTypeMsg)
		}
		return false
	}

	val, err := strconv.Atoi(vPort.GetValue())
	if err != nil {
		// If vPort is a NodePort GetValue will always return a string so this
		// is not needed actually
		if logger.Log != nil {
			logger.Log.Errorf(InvalidPortNumberMsg, vPort.GetValue())
		}
		return false
	}

	var res bool
	if np.portRange {
		res = np.low <= val && val <= np.high
		if np.not {
			return !res
		}
		return res
	}

	res = utils.InInts(val, np.list)
	if np.not {
		return !res
	}
	return res
}

func (np NodePort) match(port NodeValue) bool {
	vPort := port.(NodePort)

	if np.portRange {
		if vPort.IsRange() {
			low, high := vPort.GetRange()
			if np.low == low && np.high == high {
				return true
			}
			return false
		}

		portList := vPort.GetList()
		if (np.high - np.low) != len(portList)-1 {
			return false
		}

		for _, p := range portList {
			if p < np.low || p > np.high {
				return false
			}
		}
		return true
	}

	// np is a list
	if vPort.IsRange() {
		low, high := vPort.GetRange()
		if (high - low) != len(np.list)-1 {
			return false
		}

		for _, p := range np.list {
			if p < low || p > high {
				return false
			}
		}
		return true
	}

	// Both are lists
	portList := vPort.GetList()
	if len(np.list) != len(portList) {
		return false
	}

	for idx, p := range np.list {
		if portList[idx] != p {
			return false
		}
	}
	return true

}

// MatchB checks whether the argument's value match with the node value
func (np NodePort) MatchB(port NodeValue) bool {
	vPort := port.(NodePort)
	var vValue NodePort = vPort
	var value NodePort = np

	if vPort.HasNot() {
		vValue = vPort.GetInverse()
	}

	if np.not {
		value = np.GetInverse()
	}

	return value.match(vValue)
}

func (np NodePort) GetInverse() NodePort {
	var newValue []string
	var newNodePort NodePort

	key := np.GetKey()

	if np.portRange {
		for i := minPortInt; i < np.low; i++ {
			newValue = append(newValue, strconv.Itoa(i))
		}
		for i := np.high + 1; i <= maxPortInt; i++ {
			newValue = append(newValue, strconv.Itoa(i))
		}
	} else {
		for i := minPortInt; i <= maxPortInt; i++ {
			if !utils.InInts(i, np.list) {
				newValue = append(newValue, strconv.Itoa(i))
			}
		}
	}

	switch NodeTypeLookUp[key] {
	case SrcPort:
		newNodePort, _ = NewSrcPort(strings.Join(newValue, ","))
	case DstPort:
		newNodePort, _ = NewDstPort(strings.Join(newValue, ","))
	}

	return newNodePort
}

// GetKey returns the key associated to the node which is also part of the keywords
func (np NodePort) GetKey() string {
	return np.key
}

// GetValue returns a string version of the node value
func (np NodePort) GetValue() string {
	if np.portRange {
		high := strconv.Itoa(np.high)
		low := strconv.Itoa(np.low)
		return low + ":" + high
	}

	return strings.Join(np.listS, ",")

}

// GetOriginal returns a string version of the node value without parsing
func (np NodePort) GetOriginal() string {
	return np.original
}
