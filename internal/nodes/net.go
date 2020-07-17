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
	"net"
	"regexp"
	"strings"

	"github.com/mole-ids/mole/internal/utils"
	"github.com/pkg/errors"
)

var (
	netValueRe = regexp.MustCompile(`^!?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?(,\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?)*`)
)

// NodeNet represents proto node
type NodeNet struct {
	key      string
	netList  []*net.IPNet
	netListS []string
	not      bool
	original string
}

// NewSrcNet returns a new NodeNet node with `src` as key
func NewSrcNet(value interface{}) (NodeNet, error) {
	return nodeNet(SrcNet.String(), value)
}

// NewDstNet returns a new NodeNet node with `dst` as key
func NewDstNet(value interface{}) (NodeNet, error) {
	return nodeNet(DstNet.String(), value)
}

func nodeNet(key string, value interface{}) (ipnet NodeNet, err error) {
	sValue, ok := value.(string)
	if !ok {
		return ipnet, ErrConversionType
	}

	if reValue := netValueRe.FindString(sValue); len(reValue) > 0 {
		sValue = reValue
	} else {
		return ipnet, ErrInputDataNotValid
	}

	var netList []*net.IPNet
	var netListS []string
	var original string = sValue
	var not bool = false

	if strings.HasPrefix(sValue, notOp) {
		not = true
		sValue = strings.Replace(sValue, notOp, "", -1)
	}

	nets := strings.Split(sValue, SequenceSplitter)

	for _, n := range nets {
		if !strings.Contains(n, maskSplitter) {
			n = n + ipMask
		}

		_, nv4, err := net.ParseCIDR(n)
		if err != nil {
			// This will never happened, but leave it for precaution
			return ipnet, errors.Wrap(err, WhileParsingCIDRMsg)
		}

		netList = append(netList, nv4)
		netListS = append(netListS, n)
	}

	ipnet = NodeNet{
		key:      key,
		netList:  netList,
		netListS: netListS,
		not:      not,
		original: original,
	}

	return ipnet, err
}

// GetList returns the list of address if any or a empty list
func (nn NodeNet) GetList() []*net.IPNet {
	return nn.netList
}

// GetListS returns the list of address if any or a empty list
func (nn NodeNet) GetListS() []string {
	return nn.netListS
}

// HasNot returns whether the node has not operator
func (nn NodeNet) HasNot() bool {
	return nn.not
}

// Match checks whether the argument's value match with the node value
func (nn NodeNet) Match(addr NodeValue) bool {
	vAddr, ok := addr.(NodeNet)
	if !ok {
		return false
	}

	netList := vAddr.GetParsedValue()

	if len(netList) <= 0 {
		return false
	}

	return utils.InNets(netList[0], nn.netList)

}

func (nn NodeNet) match(addr NodeValue) bool {
	vAddr, ok := addr.(NodeNet)
	if !ok {
		return false
	}

	vListS := vAddr.GetListS()
	// // both list should length equally
	// if len(nn.netListS) != len(vListS) {
	// 	// This can be optimized by taking into account each net in the lists
	// 	return false
	// }

	for _, n := range vListS {
		if !utils.InStrings(n, nn.netListS) {
			return false
		}
	}

	return true
}

// MatchB checks whether the argument's value match with the node value
func (nn NodeNet) MatchB(addr NodeValue) bool {
	vNet, ok := addr.(NodeNet)
	if !ok {
		return false
	}

	if nn.match(addr) {
		if (nn.not == true && vNet.HasNot() == true) || (nn.not == false && vNet.HasNot() == false) {
			return true
		}
		return false
	}

	return false
}

// GetKey returns the key associated to the node which is also part of the keywords
func (nn NodeNet) GetKey() string {
	return nn.key
}

// GetValue returns a string version of the node value
func (nn NodeNet) GetValue() string {
	return strings.Join(nn.netListS, ",")
}

// GetParsedValue returns a string version of the node value
func (nn NodeNet) GetParsedValue() []*net.IPNet {
	return nn.netList
}

// GetOriginal returns a string version of the node value without parsing
func (nn NodeNet) GetOriginal() string {
	return nn.original
}
