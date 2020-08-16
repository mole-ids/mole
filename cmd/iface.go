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
package cmd

import (
	"fmt"
	"log"
	"os"
	"text/tabwriter"

	"github.com/google/gopacket/pcap"
	"github.com/mole-ids/mole/pkg/logger"
	"github.com/spf13/cobra"
)

// ifaceCmd iface command
var ifaceCmd = &cobra.Command{
	Use:   "interfaces",
	Short: "list interfaces",
	PreRun: func(cmd *cobra.Command, args []string) {
		if val, err := cmd.Flags().GetBool("version"); err == nil && val {
			fmt.Printf("%s %s\nBuilt datetime: %s\nBuild Hash: %s\n", AppName, Version, BuildDate, BuildHash)
			os.Exit(0)
		} else if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		err := logger.New()
		if err != nil {
			fmt.Printf("Err: %s\n", err.Error())
		}
	},
	Run: runIfaceCmd,
}

func init() {
	// Adding ids to the main root command
	RootCmd.AddCommand(ifaceCmd)
}

// runIfaceCmd executes ids command
func runIfaceCmd(cmd *cobra.Command, args []string) {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Unable to retrieve the interface information because: %s", err.Error())
	}

	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 0, '\t', 0)
	fmt.Fprintln(w, "Description\tName")
	for _, iface := range ifaces {
		var desc string = "<empty>"
		if iface.Description != "" {
			desc = iface.Description
		}
		fmt.Fprintf(w, "%s\t%s\n", desc, iface.Name)
	}
	w.Flush()
}
