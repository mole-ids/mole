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
package tree

import (
	"testing"

	"github.com/mole-ids/mole/internal/nodes"
	"github.com/mole-ids/mole/internal/types"
	"github.com/mole-ids/mole/pkg/logger"
)

func TestMain(tm *testing.M) {
	logger.New()
	tm.Run()
}

func getDummyData() []types.MetaRule {
	var metarules []types.MetaRule

	var data map[string][]string
	data = make(map[string][]string)

	values := 3

	data["proto"] = []string{"tcp", "tcp", "udp"}
	data["src"] = []string{"192.168.0.1", "192.168.2.1", "192.168.3.1"}
	data["sport"] = []string{"123", "123", "123"}
	data["dst"] = []string{"172.16.0.1", "172.16.2.1", "172.16.3.1"}
	data["dport"] = []string{"123", "123", "123"}

	for idx := 0; idx < values; idx++ {
		meta := make(types.MetaRule)
		for k, v := range data {
			node, _ := nodes.GetNodeValue(k, v[idx])
			meta[k] = node
		}
		metarules = append(metarules, meta)
	}
	return metarules
}

func getDummyData2() []types.MetaRule {
	var metarules []types.MetaRule

	var data map[string][]string
	data = make(map[string][]string)

	values := 3

	data["proto"] = []string{"tcp", "tcp", "udp"}
	data["src"] = []string{"192.168.0.1", "192.168.2.1", "192.168.3.1"}
	data["sport"] = []string{"123", "123", "123"}
	data["dst"] = []string{"172.16.0.1", "172.16.2.1", "172.16.3.1"}
	data["dport"] = []string{"123", "123", "123"}

	for idx := 0; idx < values; idx++ {
		meta := make(types.MetaRule)
		for k, v := range data {
			node, _ := nodes.GetNodeValue(k, v[idx])
			meta[k] = node
		}
		metarules = append(metarules, meta)
	}
	return metarules
}

func TestFindInsert(t *testing.T) {

	Decision = New(nodes.NewRoot())

	for _, rule := range getDummyData() {
		lvl := 0
		node, ok, err := insertRule(Decision, lvl, nodes.Keywords, rule)
		if node == nil {
			t.Error("Expecting node, but a nil was found")
		}

		if !ok {
			t.Error("Exception the result to be true, but found false")
		}

		if err != nil {
			t.Errorf("Expecting no errors but found: %s", err.Error())
		}
	}

}

func TestLookupIDNotInit(t *testing.T) {
	// Avoid any previous initialization
	Decision = nil

	data := getDummyData()
	id, err := LookupID(data[0])

	if id != "" {
		t.Errorf("Expecting ID to be empty, but found: %v", id)
	}

	if err == nil {
		t.Error("Expecting error, but non found")
	}
}

func TestLookupID(t *testing.T) {
	var ids []string
	var id string
	var idNode *Tree
	var err error

	data := getDummyData()
	Decision = New(nodes.NewRoot())

	for _, rule := range data {
		lvl := 0
		idNode, _, _ = insertRule(Decision, lvl, nodes.Keywords, rule)

		id = idNode.Value.GetValue()
		ids = append(ids, id)
	}

	for idx, pkg := range data {
		id, err = LookupID(pkg)
		if err != nil {
			t.Errorf("Expecting no errors, but found: %s", err.Error())
		}

		if id != ids[idx] {
			t.Errorf("Expecting ID '%s', to be %s", ids[idx], id)
		}
	}
}

func TestLookupIDNotFound(t *testing.T) {
	var id string
	var err error

	rulesMeta := getDummyData()

	Decision = New(nodes.NewRoot())

	lvl := 0
	_, _, _ = insertRule(Decision, lvl, nodes.Keywords, rulesMeta[0])

	id, err = LookupID(rulesMeta[1])

	if err == nil {
		t.Error("Expecting error 'solution not found', but nil was found")
	}

	if id != "" {
		t.Errorf("Expecting id to be empty, but found %s", id)
	}
}
