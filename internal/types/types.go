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
	"github.com/hillu/go-yara/v4"
	"github.com/mole-ids/mole/internal/nodes"
)

// MetaRule defines yara rule metadata
// MetaRule use as key the Keywords defined also in this package
type MetaRule map[string]nodes.NodeValue

// RuleMapScanner defines the Yara scanners to execute for each ID
type RuleMapScanner map[string]*yara.Scanner

const (
	// YaraNamespace the Yara rules namespace
	YaraNamespace = "Mole"
)
