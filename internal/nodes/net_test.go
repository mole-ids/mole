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
	"testing"
)

func TestNetNode(t *testing.T) {
	testCase := []struct {
		input      string
		checkValue string
		value      string
		original   string
		parsed     []*net.IPNet
		err        bool
		match      bool
	}{{
		input:      "192.168.0.1",
		checkValue: "192.168.0.1",
		value:      "192.168.0.1/32",
		original:   "192.168.0.1",
		parsed: []*net.IPNet{&net.IPNet{
			IP:   net.IPv4(192, 168, 0, 1),
			Mask: net.CIDRMask(32, 32),
		}},
		err:   false,
		match: true,
	}, {
		input:      "!192.168.0.1",
		checkValue: "192.168.0.1",
		value:      "192.168.0.1/32",
		original:   "!192.168.0.1",
		parsed: []*net.IPNet{&net.IPNet{
			IP:   net.IPv4(192, 168, 0, 1),
			Mask: net.CIDRMask(32, 32),
		}},
		err:   false,
		match: false,
	}, {
		input:      "192.168.0.1",
		checkValue: "!192.168.0.1",
		value:      "192.168.0.1/32",
		original:   "192.168.0.1",
		parsed: []*net.IPNet{&net.IPNet{
			IP:   net.IPv4(192, 168, 0, 1),
			Mask: net.CIDRMask(32, 32),
		}},
		err:   false,
		match: false,
	}, {
		input:      "!192.168.0.1",
		checkValue: "!192.168.0.1",
		value:      "192.168.0.1/32",
		original:   "!192.168.0.1",
		parsed: []*net.IPNet{&net.IPNet{
			IP:   net.IPv4(192, 168, 0, 1),
			Mask: net.CIDRMask(32, 32),
		}},
		err:   false,
		match: true,
	}, {
		input:      "192.168.0.1",
		checkValue: "192.168.0.2",
		value:      "192.168.0.1/32",
		original:   "192.168.0.1",
		parsed: []*net.IPNet{&net.IPNet{
			IP:   net.IPv4(192, 168, 0, 1),
			Mask: net.CIDRMask(32, 32),
		}},
		err:   false,
		match: false,
	}, {
		input:      "192.168.0.0/24",
		checkValue: "192.168.0.2",
		value:      "192.168.0.0/24",
		original:   "192.168.0.0/24",
		parsed: []*net.IPNet{&net.IPNet{
			IP:   net.IPv4(192, 168, 0, 0),
			Mask: net.CIDRMask(24, 32),
		}},
		err:   false,
		match: false,
	}, {
		input:      "192.168.0.1",
		checkValue: "!192.168.0.2",
		value:      "192.168.0.1/32",
		original:   "192.168.0.1",
		parsed: []*net.IPNet{&net.IPNet{
			IP:   net.IPv4(192, 168, 0, 1),
			Mask: net.CIDRMask(32, 32),
		}},
		err:   false,
		match: false,
	}, {
		input:      "192.168.0.1,192.168.0.2",
		checkValue: "192.168.0.2",
		value:      "192.168.0.1/32,192.168.0.2/32",
		original:   "192.168.0.1,192.168.0.2",
		parsed: []*net.IPNet{&net.IPNet{
			IP:   net.IPv4(192, 168, 0, 1),
			Mask: net.CIDRMask(32, 32),
		}, &net.IPNet{
			IP:   net.IPv4(192, 168, 0, 2),
			Mask: net.CIDRMask(32, 32),
		}},
		err:   false,
		match: true,
	}, {
		input:      "!192.168.0.1,192.168.0.2",
		checkValue: "192.168.0.2",
		value:      "192.168.0.1/32,192.168.0.2/32",
		original:   "!192.168.0.1,192.168.0.2",
		parsed: []*net.IPNet{&net.IPNet{
			IP:   net.IPv4(192, 168, 0, 1),
			Mask: net.CIDRMask(32, 32),
		}, &net.IPNet{
			IP:   net.IPv4(192, 168, 0, 2),
			Mask: net.CIDRMask(32, 32),
		}},
		err:   false,
		match: false,
	}, {
		input:      "192.168.0.1,192.168.0.2",
		checkValue: "!192.168.0.2",
		value:      "192.168.0.1/32,192.168.0.2/32",
		original:   "192.168.0.1,192.168.0.2",
		parsed: []*net.IPNet{&net.IPNet{
			IP:   net.IPv4(192, 168, 0, 1),
			Mask: net.CIDRMask(32, 32),
		}, &net.IPNet{
			IP:   net.IPv4(192, 168, 0, 2),
			Mask: net.CIDRMask(32, 32),
		}},
		err:   false,
		match: false,
	}, {
		input:      "!192.168.0.1,192.168.0.2",
		checkValue: "!192.168.0.2",
		value:      "192.168.0.1/32,192.168.0.2/32",
		original:   "!192.168.0.1,192.168.0.2",
		parsed: []*net.IPNet{&net.IPNet{
			IP:   net.IPv4(192, 168, 0, 1),
			Mask: net.CIDRMask(32, 32),
		}, &net.IPNet{
			IP:   net.IPv4(192, 168, 0, 2),
			Mask: net.CIDRMask(32, 32),
		}},
		err:   false,
		match: true,
	}, {
		input:      "192.168.0.1:192.168.0.2",
		checkValue: "!192.168.0.2",
		value:      "192.168.0.1/32",
		original:   "192.168.0.1",
		parsed: []*net.IPNet{&net.IPNet{
			IP:   net.IPv4(192, 168, 0, 1),
			Mask: net.CIDRMask(32, 32),
		}},
		err:   false,
		match: false,
	}, {
		input:      "a",
		checkValue: "!192.168.0.2",
		value:      "a",
		original:   "a",
		parsed:     nil,
		err:        true,
		match:      false,
	}}

	for idx, tc := range testCase {
		nn, err := NewSrcNet(tc.input)

		if tc.err && err == nil {
			t.Errorf("[%d] Expecting error, but none was found", idx)
		}

		if !tc.err && err != nil {
			t.Errorf("[%d] Expecting no error, but found %s", idx, err.Error())
			continue
		}

		if tc.err && err != nil {
			// Skip recognized errors
			continue
		}

		if nn.GetKey() != SrcNet.String() {
			t.Errorf("[%d] Net Src node's key should be %s, but found %s", idx, SrcNet.String(), nn.GetKey())
		}

		if nn.GetValue() != tc.value {
			t.Errorf("[%d] Net Src node's value should be %s, but found %s", idx, tc.value, nn.GetValue())
		}

		if nn.GetOriginal() != tc.original {
			t.Errorf("[%d] Net Src node's original value should be %s, but found %s", idx, tc.original, nn.GetOriginal())
		}

		if tc.parsed != nil {
			parsed := nn.GetParsedValue()
			if len(tc.parsed) != len(parsed) {
				t.Errorf("[%d] Expecting same length (%d) in parsed elements", idx, len(parsed))

			} else {
				for jdx, n := range tc.parsed {
					if n.String() != parsed[jdx].String() {
						t.Errorf("[%d][%d] Parsed net %s should be equal to %s, but they do not match", idx, jdx, n.String(), parsed[jdx].String())
					}
				}
			}
		}

		aux, _ := NewSrcNet(tc.checkValue)

		if tc.match && !nn.MatchB(aux) {
			t.Errorf("[%d] Expecting Net Src node aux (%s) to match with (%s), but they don't", idx, aux.GetOriginal(), nn.GetOriginal())
		}

		if !tc.match && nn.MatchB(aux) {
			t.Errorf("[%d] Expecting Net Src node aux (%s) to not match with (%s), but they do", idx, aux.GetOriginal(), nn.GetOriginal())
		}
	}
}

func TestMatchNet(t *testing.T) {
	testCase := []struct {
		input      string
		checkValue string
		match      bool
	}{{
		input:      "",
		checkValue: "",
		match:      false,
	}}

	for idx, tc := range testCase {
		np, _ := NewSrcNet(tc.input)
		npn, _ := NewSrcNet(tc.checkValue)

		if tc.match && !np.Match(npn) {
			t.Errorf("[%d] Expecting net nodes %s and %s to match, but they don't", idx, np.GetValue(), npn.GetValue())
		}

		if !tc.match && np.Match(npn) {
			t.Errorf("[%d] Expecting net nodes %s and %s do not match, but they do", idx, np.GetValue(), npn.GetValue())
		}
	}
}

func TestOtherErrors(t *testing.T) {
	_, err := NewSrcNet(1)
	if err == nil {
		t.Error("NetNode shouldn't be able to use other types than strings, but it does")
	}

	aux, _ := NewSrcNet("192.168.0.2")
	ni := NewID()

	if aux.match(ni) {
		t.Error("NetNode shouldn't be able to match against other NodeTypes than NetNode")
	}

	if aux.MatchB(ni) {
		t.Error("NetNode shouldn't be able to MatchB against other NodeTypes than NetNode")
	}

	if aux.Match(ni) {
		t.Error("NetNode shouldn't be able to match against other NodeTypes than NetNode")
	}
}

func TestOtherFeatures(t *testing.T) {
	aux, _ := NewSrcNet("192.168.0.2")

	if len(aux.GetList()) != 1 {
		t.Errorf("Expecting a list of nets size 1, but found a list of size %d", len(aux.GetList()))
	}

	aux, _ = NewSrcNet("192.168.0.1,192.168.0.2")

	if len(aux.GetList()) != 2 {
		t.Errorf("Expecting a list of nets size 2, but found a list of size %d", len(aux.GetList()))
	}
}
