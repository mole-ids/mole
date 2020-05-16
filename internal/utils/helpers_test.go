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
package utils

import (
	"testing"
)

func Test_inStrings(t *testing.T) {
	testCase := []struct {
		Key    string
		Slice  []string
		Result bool
	}{{
		Key:    "a",
		Slice:  []string{"a", "b"},
		Result: true,
	}, {
		Key:    "c",
		Slice:  []string{"a", "b"},
		Result: false,
	}, {
		Key:    "a",
		Slice:  []string{},
		Result: false,
	}}

	for _, tc := range testCase {
		res := InStrings(tc.Key, tc.Slice)
		if res != tc.Result {
			t.Errorf("Expecting result to be %t, but found %t", tc.Result, res)
		}
	}
}

func Test_inInts(t *testing.T) {
	testCase := []struct {
		Key    int
		Slice  []int
		Result bool
	}{{
		Key:    1,
		Slice:  []int{1, 2},
		Result: true,
	}, {
		Key:    1,
		Slice:  []int{2, 3},
		Result: false,
	}, {
		Key:    1,
		Slice:  []int{},
		Result: false,
	}}

	for _, tc := range testCase {
		res := InInts(tc.Key, tc.Slice)
		if res != tc.Result {
			t.Errorf("Expecting result to be %t, but found %t", tc.Result, res)
		}
	}
}
