package tree

import (
	"testing"

	"github.com/jpalanco/mole/internal/types"
)

func getDummyData() []types.MetaRule {
	var metarules []types.MetaRule

	var data map[string][]string
	data = make(map[string][]string)

	values := 3

	data["proto"] = []string{"TCP", "TCP", "UDP"}
	data["src"] = []string{"192.168.0.1", "192.168.2.1", "192.168.3.1"}
	data["src_port"] = []string{"123", "123", "123"}
	data["dst"] = []string{"172.16.0.1", "172.16.2.1", "172.16.3.1"}
	data["dst_port"] = []string{"123", "123", "123"}

	for idx := 0; idx < values; idx++ {
		meta := make(types.MetaRule)
		for k, v := range data {
			node, _ := types.GetNodeValue(k, v[idx])
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

	data["proto"] = []string{"TCP", "TCP", "UDP"}
	data["src"] = []string{"192.168.0.1", "192.168.2.1", "192.168.3.1"}
	data["src_port"] = []string{"123", "123", "123"}
	data["dst"] = []string{"172.16.0.1", "172.16.2.1", "172.16.3.1"}
	data["dst_port"] = []string{"123", "123", "123"}

	for idx := 0; idx < values; idx++ {
		meta := make(types.MetaRule)
		for k, v := range data {
			node, _ := types.GetNodeValue(k, v[idx])
			meta[k] = node
		}
		metarules = append(metarules, meta)
	}
	return metarules
}

func TestFindInsert(t *testing.T) {

	Decision = New(types.NewMRRoot())

	for _, rule := range getDummyData() {
		lvl := 0
		node, ok, err := insertRule(Decision, lvl, types.Keywords, rule)
		if node == nil {
			t.Error("Expecting node, but a nil was found")
		}

		if !ok {
			t.Error("Expection the result to be true, but found false")
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
	Decision = New(types.NewMRRoot())

	for _, rule := range data {
		lvl := 0
		idNode, _, _ = insertRule(Decision, lvl, types.Keywords, rule)

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

	Decision = New(types.NewMRRoot())

	lvl := 0
	_, _, _ = insertRule(Decision, lvl, types.Keywords, rulesMeta[0])

	id, err = LookupID(rulesMeta[1])

	if err == nil {
		t.Error("Expecting error 'solution not found', but nil was found")
	}

	if id != "" {
		t.Errorf("Expecting id to be empty, but found %s", id)
	}
}
