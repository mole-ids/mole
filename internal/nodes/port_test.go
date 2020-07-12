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
	"testing"

	"github.com/mole-ids/mole/pkg/logger"
)

func TestMain(tm *testing.M) {
	logger.New()
	tm.Run()
}

func TestPort(t *testing.T) {
	testCase := []struct {
		input      string
		checkValue string
		value      string
		original   string
		err        bool
		match      bool
	}{{
		input:      "1",
		checkValue: "1",
		value:      "1",
		original:   "1",
		err:        false,
		match:      true,
	}, {
		input:      "!1",
		checkValue: "1",
		value:      "1",
		original:   "!1",
		err:        false,
		match:      false,
	}, {
		input:      "1",
		checkValue: "!1",
		value:      "1",
		original:   "1",
		err:        false,
		match:      false,
	}, {
		input:      "!1",
		checkValue: "!1",
		value:      "1",
		original:   "!1",
		err:        false,
		match:      true,
	}, {
		input:      "0:10",
		checkValue: "0:10",
		value:      "0:10",
		original:   "0:10",
		err:        false,
		match:      true,
	}, {
		input:      "!0:10",
		checkValue: "0:10",
		value:      "0:10",
		original:   "!0:10",
		err:        false,
		match:      false,
	}, {
		input:      "0:10",
		checkValue: "!0:10",
		value:      "0:10",
		original:   "0:10",
		err:        false,
		match:      false,
	}, {
		input:      "!0:10",
		checkValue: "!0:10",
		value:      "0:10",
		original:   "!0:10",
		err:        false,
		match:      true,
	}, {
		input:      "0,1,2,3,4,5",
		checkValue: "0:5",
		value:      "0,1,2,3,4,5",
		original:   "0,1,2,3,4,5",
		err:        false,
		match:      true,
	}, {
		input:      "!0,1,2,3,4,5",
		checkValue: "0:5",
		value:      "0,1,2,3,4,5",
		original:   "!0,1,2,3,4,5",
		err:        false,
		match:      false,
	}, { // 10
		input:      "0,1,2,3,4,5",
		checkValue: "!0:5",
		value:      "0,1,2,3,4,5",
		original:   "0,1,2,3,4,5",
		err:        false,
		match:      false,
	}, {
		input:      "!0,1,2,3,4,5",
		checkValue: "!0:5",
		value:      "0,1,2,3,4,5",
		original:   "!0,1,2,3,4,5",
		err:        false,
		match:      true,
	}, {
		input:      "0:5",
		checkValue: "0,1,2,3,4,5",
		value:      "0:5",
		original:   "0:5",
		err:        false,
		match:      true,
	}, {
		input:      "!0:5",
		checkValue: "0,1,2,3,4,5",
		value:      "0:5",
		original:   "!0:5",
		err:        false,
		match:      false,
	}, {
		input:      "0:5",
		checkValue: "!0,1,2,3,4,5",
		value:      "0:5",
		original:   "0:5",
		err:        false,
		match:      false,
	}, {
		input:      "!0:5",
		checkValue: "!0,1,2,3,4,5",
		value:      "0:5",
		original:   "!0:5",
		err:        false,
		match:      true,
	}, {
		input:      "a",
		checkValue: "0",
		value:      "",
		original:   "a",
		err:        true,
		match:      false,
	}, {
		input:      "-1:",
		checkValue: "0",
		value:      "",
		original:   "-1",
		err:        true,
		match:      false,
	}, {
		input:      ":70000",
		checkValue: "0",
		value:      "0:7000",
		original:   ":7000",
		err:        false,
		match:      false,
	}, {
		input:      ":00000",
		checkValue: "0",
		value:      "0:0000",
		original:   ":0000",
		err:        true,
		match:      false,
	}, { // 20
		input:      "00000:",
		checkValue: "0",
		value:      "0000",
		original:   "0000",
		err:        false,
		match:      true,
	}, {
		input:      "1:",
		checkValue: "0",
		value:      "1:65535",
		original:   "1:",
		err:        false,
		match:      false,
	}, {
		input:      "1:5",
		checkValue: "1:6",
		value:      "1:5",
		original:   "1:5",
		err:        false,
		match:      false,
	}, {
		input:      "1:5",
		checkValue: "1,2,3,4,6",
		value:      "1:5",
		original:   "1:5",
		err:        false,
		match:      false,
	}, {
		input:      "1,2,3,4,5",
		checkValue: "0:4",
		value:      "1,2,3,4,5",
		original:   "1,2,3,4,5",
		err:        false,
		match:      false,
	}, {
		input:      "1,2,3,4,5",
		checkValue: "0,2,3,4,5",
		value:      "1,2,3,4,5",
		original:   "1,2,3,4,5",
		err:        false,
		match:      false,
	}, {
		input:      "!5:10",
		checkValue: "0,2,3,4,5",
		value:      "5:10",
		original:   "!5:10",
		err:        false,
		match:      false,
	}}

	for idx, tc := range testCase {
		np, err := NewSrcPort(tc.input)

		if tc.err && err == nil {
			t.Errorf("[%d] Expecting error when creating port node with %s as input, but no error found", idx, tc.input)
		}

		if !tc.err && err != nil {
			// np won't be defined
			t.Errorf("[%d] Expecting no error when creating port node with %s as input, but found %s", idx, tc.input, err.Error())
			continue
		}

		if tc.err && err != nil {
			// Skip recognized errors
			continue
		}

		if np.GetKey() != SrcPort.String() {
			t.Errorf("[%d] Port node's key should be %s, but found %s", idx, SrcPort.String(), np.GetKey())
		}

		if np.GetValue() != tc.value {
			t.Errorf("[%d] Port node's value should be %s, but found %s", idx, tc.value, np.GetValue())
		}

		if np.GetOriginal() != tc.original {
			t.Errorf("[%d] Port node's original value should be %s, but found %s", idx, tc.original, np.GetOriginal())
		}

		aux, _ := NewSrcPort(tc.checkValue)

		if tc.match && !np.MatchB(aux) {
			t.Errorf("[%d] Expecting port node aux (%s) to match with (%s), but they don't", idx, aux.GetValue(), np.GetValue())
		}

		if !tc.match && np.MatchB(aux) {
			t.Errorf("[%d] Expecting port node aux (%s) to not match with (%s), but they do", idx, aux.GetValue(), np.GetValue())
		}
	}
}

func TestMatchPort(t *testing.T) {
	testCase := []struct {
		input      string
		checkValue string
		match      bool
	}{{
		input:      "1",
		checkValue: "1",
		match:      true,
	}, {
		input:      "1",
		checkValue: "2",
		match:      false,
	}, {
		input:      "1:2",
		checkValue: "1",
		match:      true,
	}, {
		input:      "1:2",
		checkValue: "3",
		match:      false,
	}, {
		input:      "1,2,3",
		checkValue: "2",
		match:      true,
	}, {
		input:      "1,2,3",
		checkValue: "4",
		match:      false,
	}, {
		input:      "!1",
		checkValue: "2",
		match:      true,
	}, {
		input:      "!1",
		checkValue: "1",
		match:      false,
	}, {
		input:      "!1,2,3",
		checkValue: "4",
		match:      true,
	}, {
		input:      "!1,2,3",
		checkValue: "1",
		match:      false,
	}, {
		input:      "!1:2",
		checkValue: "3",
		match:      true,
	}, {
		input:      "!1:2",
		checkValue: "2",
		match:      false,
	}}

	for idx, tc := range testCase {
		np, _ := NewSrcPort(tc.input)
		npn, _ := NewSrcPort(tc.checkValue)

		if tc.match && !np.Match(npn) {
			t.Errorf("[%d] Expecting port nodes %s and %s to match, but they don't", idx, np.GetValue(), npn.GetValue())
		}

		if !tc.match && np.Match(npn) {
			t.Errorf("[%d] Expecting port nodes %s and %s do not match, but they do", idx, np.GetValue(), npn.GetValue())
		}
	}

	np, _ := NewSrcPort("1")
	nid := NewID()

	if np.Match(nid) {
		t.Error("NodePort can not match with a different node type")
	}

}

func TestNewWrong(t *testing.T) {
	_, err := NewDstPort(1)

	if err == nil {
		t.Error("Expecting error but none found")
	}
}

func TestDstPortNode(t *testing.T) {
	np, err := NewDstPort("123")

	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
		return
	}

	if np.GetKey() != DstPort.String() {
		t.Errorf("Node destination port exect as key %s, but found %s", DstPort.String(), np.GetKey())
	}

	npAux, _ := NewDstPort("!123")

	if np.MatchB(npAux) {
		t.Errorf("Expecting %s do not match with %s but it does", np.GetValue(), npAux.GetValue())
	}
}

func TestGetWrong(t *testing.T) {
	np, _ := NewDstPort("123")

	list := np.GetList()

	if len(list) == 0 {
		t.Error("Expecting port list to be higher than 0, but it is 0")
	}

	l, h := np.GetRange()
	if l != -1 || h != -1 {
		t.Errorf("Expecting no range but found one %d:%d", l, h)
	}

}
