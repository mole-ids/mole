package tree

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jpalanco/mole/pkg/rules"
	"github.com/k0kubun/pp"
)

var ruleMetas = []map[string]string{{
	"type":     "alert",
	"proto":    "tcp",
	"src":      "192.168.0.0/24",
	"src_port": "(t) any",
	"dst":      "0.0.0.0",
	"dst_port": "(t) any",
}, {
	"type":     "alert",
	"proto":    "udp",
	"src":      "0.0.0.0",
	"src_port": "(u) any",
	"dst":      "0.0.0.0",
	"dst_port": "(u) any",
}, {
	"type":     "alert",
	"proto":    "tcp",
	"src":      "192.168.0.0/16",
	"src_port": "(tt) any",
	"dst":      "0.0.0.0",
	"dst_port": "(tt) any",
},
}

func TestFindInsert(t *testing.T) {

	r := New(NodeVal{})
	for _, rule := range ruleMetas {
		lvl := 0
		fmt.Println(InsertRule(r, lvl, rules.Keywords, rule))
	}

	pp.Println(r)

}

type NodeVal struct {
	t string
	v string
}

func (nv NodeVal) Match(n rules.NodeValue) bool {
	res := strings.Compare(nv.v, n.(NodeVal).v)
	if nv.t == "src" {
		fmt.Printf("SRC - MATCH & REPLACE || %s:%s::%s:%s\n", nv.t, n.(NodeVal).t, nv.v, n.(NodeVal).v)
		return true
	}
	return res == 0
}

func (nv NodeVal) GetKey() string {
	return nv.t
}

func (nv NodeVal) GetValue() string {
	return nv.v
}

func (nv NodeVal) SetValue(value interface{}) error {
	v, ok := value.(string)
	if !ok {
		return errors.New("unable to convert value")
	}
	nv.v = v
	return nil
}
