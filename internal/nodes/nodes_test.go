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

func TestGetNodeValue(t *testing.T) {
	testCase := []struct {
		nodeType  string
		nodeValue string
		err       bool
	}{{
		nodeType:  "proto",
		nodeValue: "tcp",
		err:       false,
	}, {
		nodeType:  "src",
		nodeValue: "192.168.0.1",
		err:       false,
	}, {
		nodeType:  "src",
		nodeValue: "192.168.a",
		err:       true,
	}, {
		nodeType:  "sport",
		nodeValue: "192",
		err:       false,
	}, {
		nodeType:  "sport",
		nodeValue: "a",
		err:       true,
	}, {
		nodeType:  "dst",
		nodeValue: "192.168.0.1",
		err:       false,
	}, {
		nodeType:  "dst",
		nodeValue: "192.168.a",
		err:       true,
	}, {
		nodeType:  "dport",
		nodeValue: "192",
		err:       false,
	}, {
		nodeType:  "dport",
		nodeValue: "a",
		err:       true,
	}, {
		nodeType:  "id",
		nodeValue: "a",
		err:       false,
	}, {
		nodeType:  "noexist",
		nodeValue: "a",
		err:       true,
	}}

	for idx, tc := range testCase {
		_, err := GetNodeValue(tc.nodeType, tc.nodeValue)

		if tc.err && err == nil {
			t.Errorf("[%d] Expecting error when creating node type %s with value %s, but no error found", idx, tc.nodeType, tc.nodeValue)
		}
		if !tc.err && err != nil {
			t.Errorf("[%d] Expecting no error when creating node type %s with value %s, but an error found", idx, tc.nodeType, tc.nodeValue)
			continue
		}
	}

	_, err := GetNodeValue("proto", 1)

	if err == nil {
		t.Errorf("Expecting error when creating node type proto with value 1, but no error found")
	}

}
