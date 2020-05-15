package cmd

import (
	"os"
	"fmt"
	"syscall"

	"github.com/mole-ids/mole/pkg/engine"
	"github.com/mole-ids/mole/pkg/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// idsCmd ids command
var idsCmd = &cobra.Command{
	Use:   "ids",
	Short: "start Mole as IDS",
	PreRun: func(cmd *cobra.Command, args []string) {
		if val, err := cmd.Flags().GetBool("version"); err == nil && val {
			fmt.Printf("%s %s\nBuilt datetime: %s\nBuild Hash: %s\n", AppName, Version, BuildDate, BuildHash)
			os.Exit(0)
		} else if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		logger.New()
	},
	Run: runIdsCmd,
}

func init() {
	// Configure flags arguments
	idsCmd.Flags().String("iface", "", "Listen on interface")
	idsCmd.Flags().String("rulesDir", "", "Yara Rules directory")
	idsCmd.Flags().String("rulesIndex", "", "Yara Rules directory")
	idsCmd.Flags().Bool("pfring", true, "Enable PF Ring on the interface")
	idsCmd.Flags().String("bpf", "", "BPF filter")
	idsCmd.Flags().StringSlice("variables", []string{}, "Varaiables value used in the rules")

	// Bind flags to configuration file
	viper.BindPFlag("interface.iface", idsCmd.Flags().Lookup("iface"))
	viper.BindPFlag("interface.pf_ring", idsCmd.Flags().Lookup("pfring"))
	viper.BindPFlag("interface.bpf", idsCmd.Flags().Lookup("bpf"))

	viper.BindPFlag("rules.rules_dir", idsCmd.Flags().Lookup("rulesDir"))
	viper.BindPFlag("rules.rules_index", idsCmd.Flags().Lookup("rulesIndex"))
	viper.BindPFlag("rules.variables", idsCmd.Flags().Lookup("variables"))

	// Bind persistent flags from root command
	viper.BindPFlag("logger.log_to", RootCmd.PersistentFlags().Lookup("logTo"))
	viper.BindPFlag("logger.log_level", RootCmd.PersistentFlags().Lookup("logLevel"))

	// Adding ids to the main root command
	RootCmd.AddCommand(idsCmd)
}

// runIdsCmd executes ids command
func runIdsCmd(cmd *cobra.Command, args []string) {
	// Ensure user is root
	ensureRoot()

	// Start mole engine
	motor, err := engine.New()
	if err != nil {
		logger.Log.Fatalf("unable to initiate yara engine: %s", err.Error())
	}

	motor.Start()
}

// ensureRoot checks whether mole is been running as root usser
func ensureRoot() {
	if uid := syscall.Getuid(); uid != 0 {
		logger.Log.Fatal("you need to be root")

	}
}
