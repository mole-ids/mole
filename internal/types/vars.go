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

var (
	// Keywords defines what Yara metadata entries are used for processing the rule.
	// This array also defines the order in which each key is taking into account
	Keywords = []string{"proto", "src", "src_port", "dst", "dst_port"}

	// RuleDefVersion defines the version of the metadata accepted by Mole
	// this will be handy to version rules later on
	RuleDefVersion = "1.0"

	// RangeSplitter character used to define a range, like ports 80:443
	RangeSplitter = ":"
	// SequenceSplitter character used to define a sequence, like ports 80,443
	SequenceSplitter = ","
)
