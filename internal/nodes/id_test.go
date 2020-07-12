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

func TestID(t *testing.T) {
	ni := NewID()

	if ni.GetKey() != ID.String() {
		t.Errorf("ID node's key should be %s, but found %s", ID.String(), ni.GetKey())
	}

	if ni.GetValue() == "" {
		t.Error("Expecting value not to be empty, but it is")
	}

	if !ni.MatchB(ni) {
		t.Error("Expecting ID node MatchB against itself, but it does not")
	}

	if !ni.Match(ni) {
		t.Error("Expecting ID node Match against itself, but it does not")
	}
}
