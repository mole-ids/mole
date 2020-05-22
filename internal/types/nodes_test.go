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
	"strings"
	"testing"
)

func TestMRRoot(t *testing.T) {
	mr := NewMRRoot()

	// Root nodes does not implement properly the interface so checking against
	// any node will be fine
	mr1, err := NewMRProto("test")
	if err != nil {
		t.Errorf("Unexpected error %s", err.Error())
	}

	if !mr.Match(mr1) {
		t.Error("Root node match should always return true")
	}

	if mr.GetKey() != "root" {
		t.Errorf("Expecting key to be root, but found %s", mr.GetKey())
	}

	if mr.GetValue() != "" {
		t.Errorf("Expecting empty value, but found %s", mr.GetValue())
	}
}

func TestMRProto(t *testing.T) {
	testCase := []struct {
		key         string
		value       string
		expectedErr bool
		value2      string
		match       bool
	}{{
		key:         "proto",
		value:       "tcp",
		expectedErr: false,
		value2:      "tcp",
		match:       true,
	}, {
		key:         "proto",
		value:       "udp",
		expectedErr: false,
		value2:      "udp",
		match:       true,
	}, {
		key:         "proto",
		value:       "tcp",
		expectedErr: false,
		value2:      "udp",
		match:       false,
	}}

	for idx, tc := range testCase {
		mr, err := NewMRProto(tc.value)

		if tc.expectedErr && err == nil {
			t.Errorf("[%d] Expected error but none found", idx)
		}
		if !tc.expectedErr && err != nil {
			t.Errorf("[%d] Expected no error but found %s", idx, err.Error())
		}

		if mr.GetKey() != tc.key {
			t.Errorf("[%d] Expecting key to be %s, but found %s", idx, tc.key, mr.GetKey())
		}

		if mr.GetValue() != tc.value {
			t.Errorf("[%d] Expecting value to be %s, but found %s", idx, tc.value, mr.GetValue())
		}

		mr1, _ := NewMRProto(tc.value2)

		res := mr.Match(mr1)
		if res != tc.match {
			t.Errorf("[%d] Expecting nodes to match (%t), but they differ (%t)", idx, tc.match, res)
		}
	}
}

func TestMRPort(t *testing.T) {
	testCase := []struct {
		Key         string
		Port        string
		ExpectedErr bool
		Port2       string
		Match       bool
	}{{
		Key:         "src_port",
		Port:        "1",
		ExpectedErr: false,
		Port2:       "1",
		Match:       true,
	}, {
		Key:         "src_port",
		Port:        "1",
		ExpectedErr: false,
		Port2:       "2",
		Match:       false,
	}, {
		Key:         "src_port",
		Port:        "a",
		ExpectedErr: true,
		Port2:       "2",
		Match:       false,
	}, {
		Key:         "src_port",
		Port:        "1,2",
		ExpectedErr: false,
		Port2:       "2",
		Match:       true,
	}, {
		Key:         "src_port",
		Port:        "1,2,4",
		ExpectedErr: false,
		Port2:       "2",
		Match:       true,
	}, {
		Key:         "src_port",
		Port:        "1,2,4",
		ExpectedErr: false,
		Port2:       "4",
		Match:       true,
	}, {
		Key:         "src_port",
		Port:        "1,2,,4",
		ExpectedErr: false,
		Port2:       "2",
		Match:       true,
	}, {
		Key:         "src_port",
		Port:        "1,2,,4",
		ExpectedErr: false,
		Port2:       "3",
		Match:       false,
	}, {
		Key:         "src_port",
		Port:        "1,a",
		ExpectedErr: true,
		Port2:       "2",
		Match:       false,
	}, {
		Key:         "src_port",
		Port:        "1:2",
		ExpectedErr: false,
		Port2:       "2",
		Match:       true,
	}, {
		Key:         "src_port",
		Port:        "1:2",
		ExpectedErr: false,
		Port2:       "3",
		Match:       false,
	}, {
		Key:         "src_port",
		Port:        "1:",
		ExpectedErr: false,
		Port2:       "2222",
		Match:       true,
	}, {
		Key:         "src_port",
		Port:        ":443",
		ExpectedErr: false,
		Port2:       "80",
		Match:       true,
	}, {
		Key:         "src_port",
		Port:        "1:a",
		ExpectedErr: true,
		Port2:       "2",
		Match:       false,
	}, {
		Key:         "src_port",
		Port:        "1,2,4,5",
		ExpectedErr: false,
		Port2:       "2,5",
		Match:       true,
	}, {
		Key:         "src_port",
		Port:        "2,5",
		ExpectedErr: false,
		Port2:       "1,2,3,4,5",
		Match:       false,
	}, {
		Key:         "src_port",
		Port:        "1:10",
		ExpectedErr: false,
		Port2:       "2:4",
		Match:       true,
	}, {
		Key:         "src_port",
		Port:        "1,2,3,4,5,6",
		ExpectedErr: false,
		Port2:       "2:5",
		Match:       true,
	}, {
		Key:         "src_port",
		Port:        "1:10",
		ExpectedErr: false,
		Port2:       "1,2,3,4,5",
		Match:       true,
	}, {
		Key:         "src_port",
		Port:        "1:10",
		ExpectedErr: false,
		Port2:       "1:20",
		Match:       false,
	}}

	for idx, tc := range testCase {
		mr, err := NewSRCMRPort(tc.Port)

		if tc.ExpectedErr && err == nil {
			t.Errorf("[%d] Expecting error but none found", idx)
			continue
		}

		if !tc.ExpectedErr && err != nil {
			t.Errorf("[%d] Unexpecting error: %s", idx, err.Error())
		}

		if tc.ExpectedErr && err != nil {
			// avoid confision
			continue
		}

		if mr.GetKey() != tc.Key {
			t.Errorf("[%d] Expecting key to be %s, but found %s", idx, tc.Key, mr.GetKey())
		}

		if mr.GetValue() != tc.Port {
			t.Errorf("[%d] Expecting value to be %s, but found %s", idx, tc.Port, mr.GetValue())
		}

		mr1, _ := NewSRCMRPort(tc.Port2)

		res := mr.Match(mr1)
		if res != tc.Match {
			t.Errorf("[%d] Expecting nodes to match (%t), but they differ (%t)", idx, tc.Match, res)
		}
	}
}

func Test_MRAddress(t *testing.T) {
	testCase := []struct {
		Key         string
		Net         string
		ExpectedErr bool
		Net2        string
		Match       bool
	}{{
		Key:         "src",
		Net:         "192.168.0.1",
		ExpectedErr: false,
		Net2:        "192.168.0.1",
		Match:       true,
	}, {
		Key:         "src",
		Net:         "192.168.0.0/24",
		ExpectedErr: false,
		Net2:        "192.168.0.10",
		Match:       true,
	}, {
		Key:         "src",
		Net:         "192.168.0.0/24",
		ExpectedErr: false,
		Net2:        "192.168.0.0",
		Match:       true,
	}, {
		Key:         "src",
		Net:         "192.168.0.0/24",
		ExpectedErr: false,
		Net2:        "192.168.0.255",
		Match:       true,
	}, {
		Key:         "src",
		Net:         "192.168.0.0/24",
		ExpectedErr: false,
		Net2:        "192.168.1.1",
		Match:       false,
	}, {
		Key:         "src",
		Net:         "192.168.0.0/28",
		ExpectedErr: false,
		Net2:        "192.168.0.16/32",
		Match:       false,
	}, {
		Key:         "src",
		Net:         "172.16.0.0/16",
		ExpectedErr: false,
		Net2:        "192.168.0.0/24",
		Match:       false,
	}, {
		Key:         "src",
		Net:         "10.0.0.0/8",
		ExpectedErr: false,
		Net2:        "192.168.0.16/32",
		Match:       false,
	}, {
		Key:         "src",
		Net:         "192.168.0.1",
		ExpectedErr: false,
		Net2:        "192.168.0.0/24",
		Match:       false,
	}, {
		Key:         "src",
		Net:         "192.168.0.1",
		ExpectedErr: false,
		Net2:        "192.168.0.2",
		Match:       false,
	}, {
		Key:         "src",
		Net:         "192.168.0.0/24",
		ExpectedErr: false,
		Net2:        "90.90.90.90",
		Match:       false,
	}}

	for idx, tc := range testCase {
		mr, err := NewSRCMRAddress(tc.Net)

		if tc.ExpectedErr && err == nil {
			t.Errorf("[%d] Expecting error but none found", idx)
			continue
		}

		if !tc.ExpectedErr && err != nil {
			t.Errorf("[%d] Unexpecting error: %s", idx, err.Error())
		}

		if tc.ExpectedErr && err != nil {
			// avoid confision
			continue
		}

		if mr.GetKey() != tc.Key {
			t.Errorf("[%d] Expecting key to be %s, but found %s", idx, tc.Key, mr.GetKey())
		}

		val := tc.Net
		if !strings.Contains(tc.Net, "/") {
			val = tc.Net + "/32"
		}
		if mr.GetValue() != val {
			t.Errorf("[%d] Expecting value to be %s, but found %s", idx, tc.Net, mr.GetValue())
		}

		mr1, _ := NewSRCMRAddress(tc.Net2)

		res := mr.Match(mr1)
		if res != tc.Match {
			t.Errorf("[%d] Expecting nodes to match (%t), but they differ (%t)", idx, tc.Match, res)
		}
	}
}
