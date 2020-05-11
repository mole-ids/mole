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
