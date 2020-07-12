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

func TestRoot(t *testing.T) {
	nr := NewRoot()

	if nr.GetKey() != Root.String() {
		t.Errorf("Root node's key should be %s, but found %s", Root.String(), nr.GetKey())
	}

	if nr.GetValue() != "" {
		t.Errorf("Root node's value should be a empty string, byt found %s", nr.GetValue())
	}

	ni := NewID()

	if !nr.MatchB(ni) {
		t.Error("Root node's MatchB function shoud match anything")
	}

	if !nr.Match(ni) {
		t.Error("Root node's Match function shoud match anything")
	}
}
