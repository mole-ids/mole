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

import "testing"

func TestProto(t *testing.T) {
	testCase := []struct {
		input      string
		checkInput string
		value      string
		err        bool
		match      bool
	}{{
		input:      "tcp",
		checkInput: "tcp",
		value:      "tcp",
		err:        false,
		match:      true,
	}, {
		input:      "tcp",
		checkInput: "udp",
		value:      "tcp",
		err:        false,
		match:      false,
	}, {
		input:      "tcp",
		checkInput: "!udp",
		value:      "tcp",
		err:        false,
		match:      true,
	}, {
		input:      "!tcp",
		checkInput: "udp",
		value:      "tcp",
		err:        false,
		match:      true,
	}, {
		input:      "!tcp",
		checkInput: "!udp",
		value:      "tcp",
		err:        false,
		match:      false,
	}}

	for idx, tc := range testCase {
		np, err := NewProto(tc.input)
		if tc.err && err == nil {
			t.Errorf("[%d] Expecting errors but none found when creating a new protocol node", idx)
		}

		if !tc.err && err != nil {
			t.Errorf("[%d] Expecting no errors but when creating a new protocol node found %s", idx, err.Error())
			continue
		}

		if np.GetKey() != Proto.String() {
			t.Errorf("[%d] Protocol node's key should be %s, but found %s", idx, Proto.String(), np.GetKey())
		}

		if np.GetValue() != tc.value {
			t.Errorf("[%d] Expecting protocol node's value to be %s, but found %s", idx, tc.value, np.GetValue())
		}

		if np.GetOriginal() != tc.input {
			t.Errorf("[%d] Expecting protocol node's original value to be %s, but found %s", idx, tc.input, np.GetOriginal())
		}

		npAux, _ := NewProto(tc.checkInput)
		if tc.match && !np.MatchB(npAux) {
			t.Errorf("[%d] Expecting protocol node to match, but they don't (%s != %s)", idx, np.GetValue(), npAux.GetValue())
		}

		if !tc.match && np.MatchB(npAux) {
			t.Errorf("[%d] Expecting protocol node to differ, but they don't (%s == %s)", idx, np.GetValue(), npAux.GetValue())
		}
	}
}

func TestMatchOtherNodeType(t *testing.T) {
	np, _ := NewProto("tcp")
	nr := NewRoot()

	if np.Match(nr) {
		t.Error("Protocol node match only with protocol nodes, but it matched with Root node")
	}
}

func TestNewWithError(t *testing.T) {
	_, err := NewProto(1)

	if err == nil {
		t.Error("Protocol nodes accepts only strings as argument, but it accept a int instead")
	}
}
