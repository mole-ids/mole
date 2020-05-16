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
package debug

import (
	"fmt"
	"io/ioutil"

	"github.com/emicklei/dot"
	"github.com/mole-ids/mole/internal/tree"
	"github.com/mole-ids/mole/pkg/rules"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// dotCmd dot command
var dotCmd = &cobra.Command{
	Use:   "dot",
	Short: "Generates a dot version of the decision tree",
	Run:   runDotCmd,
}

func init() {
	// Dot flags configuration
	dotCmd.Flags().String("output", "stdout", "Dot output")
	dotCmd.Flags().String("rulesDir", "", "Yara Rules directory")
	dotCmd.Flags().String("rulesIndex", "", "Yara Rules directory")

	// Bind flags to configuration file
	viper.BindPFlag("debug.dot.output", dotCmd.Flags().Lookup("output"))
	viper.BindPFlag("debug.dot.rules_dir", dotCmd.Flags().Lookup("rulesDir"))
	viper.BindPFlag("debug.dot.rules_index", dotCmd.Flags().Lookup("rulesIndex"))

	// Adding dot to the main debug command
	debugCmd.AddCommand(dotCmd)
}

// runDotCmd executes dot command
func runDotCmd(cmd *cobra.Command, args []string) {
	rm, _ := rules.NewManager()
	rm.LoadRules()
	_, _ = tree.FromRules(rm.RawRules)

	g := dot.NewGraph(dot.Directed)
	transverse(g, tree.Decision, 0)

	graph := g.String()
	fmt.Println(graph)

	ioutil.WriteFile("test.gv", []byte(graph), 0666)
}

// transverse is used to walk through the rules tree in terms to build a dot graph
func transverse(g *dot.Graph, t *tree.Tree, lvl int) dot.Node {
	var key string
	if t.Children != nil {
		var parentNode, currentNode, childNode /*, nextNode*/ dot.Node

		lvl++
		key = fmt.Sprintf("%s_%d_%s", t.Value.GetKey(), lvl, t.Value.GetValue())

		// This node will be the parent node for the node returned from the
		// recursivity
		parentNode = g.Node(key).Box().Attr("value", t.Value.GetValue())
		fmt.Printf("1- Crated node %s\n", key)

		// var loop bool = false
		var hasNext bool = false
		next := t.Children
		for next != nil {
			current := next
			next = current.Next

			// if loop {
			// 	lvl++
			// 	key = fmt.Sprintf("%s_%d_%s", current.Value.GetKey(), lvl, current.Value.GetValue())
			// 	nextNode = g.Node(key).Box().Attr("value", current.Value.GetValue())

			// 	childNode.Edge(nextNode)

			// 	loop1 = true

			// }

			if next != nil {
				hasNext = true
				if key != fmt.Sprintf("%s_%d_%s", current.Value.GetKey(), lvl, current.Value.GetValue()) {
					key = fmt.Sprintf("%s_%d_%s", current.Value.GetKey(), lvl, current.Value.GetValue())
					childNode = g.Node(key).Box().Attr("value", current.Value.GetValue())
					fmt.Printf("2- Crated node %s\n", key)
				} else {
					childNode = parentNode
				}
			} else {
				hasNext = false
			}
			// if !loop && next != nil {
			// 	loop = true
			// 	lvl++
			// 	key = fmt.Sprintf("%s_%d_%s", current.Value.GetKey(), lvl, current.Value.GetValue())
			// 	childNode = g.Node(key).Box().Attr("value", current.Value.GetValue())
			// }

			currentNode = transverse(g, current, lvl+1)

			if hasNext {
				childNode.Edge(currentNode)
				currentNode.Edge(parentNode)
			} else {
				parentNode.Edge(currentNode)
				currentNode.Edge(parentNode)
			}

			// if loop1 {
			// 	parentNode.Edge(nextNode)
			// 	//nextNode.Edge(currentNode)
			// 	//currentNode.Edge(nextNode)
			// 	loop1 = false

			// } else {
			// 	// Linking current node with its parent
			// 	parentNode.Edge(currentNode)
			// 	currentNode.Edge(parentNode)
			// }
		}
		//fmt.Printf("1- Key: %s || Value: %s\n", t.Value.GetKey(), t.Value.GetValue())
		return parentNode
	}

	//fmt.Printf("2- Key: %s || Value: %s\n", t.Value.GetKey(), t.Value.GetValue())
	key = fmt.Sprintf("%s_%d_%s", t.Value.GetKey(), lvl, t.Value.GetValue())

	fmt.Printf("3- Crated node %s\n", key)
	return g.Node(key).Box().Attr("value", t.Value.GetValue())
}
