package cmd

import (
	"syscall"

	"github.com/jpalanco/mole/pkg/engine"
	"github.com/jpalanco/mole/pkg/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// idsCmd ids command
var idsCmd = &cobra.Command{
	Use:   "ids",
	Short: "start Mole as IDS",
	PreRun: func(cmd *cobra.Command, args []string) {
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
	// idsCmd.Flags().String("logTo", "", "Log to file")
	// idsCmd.Flags().String("logLevel", "info", "Log level")
	idsCmd.Flags().StringSlice("variables", []string{}, "Varaiables value used in the rules")

	// Bind flags to configuration file
	viper.BindPFlag("interface.iface", idsCmd.Flags().Lookup("iface"))
	viper.BindPFlag("interface.pf_ring", idsCmd.Flags().Lookup("pfring"))
	viper.BindPFlag("interface.bpf", idsCmd.Flags().Lookup("bpf"))

	viper.BindPFlag("rules.rules_dir", idsCmd.Flags().Lookup("rulesDir"))
	viper.BindPFlag("rules.rules_index", idsCmd.Flags().Lookup("rulesIndex"))
	viper.BindPFlag("rules.variables", idsCmd.Flags().Lookup("variables"))

	// viper.BindPFlag("logger.log_to", idsCmd.Flags().Lookup("logTo"))
	// viper.BindPFlag("logger.log_level", idsCmd.Flags().Lookup("logLevel"))

	// Adding ids to the main root command
	RootCmd.AddCommand(idsCmd)
}

// runIdsCmd executes ids command
func runIdsCmd(cmd *cobra.Command, args []string) {
	// Ensure user is root
	ensureRoot()

	motor, err := engine.New()
	if err != nil {
		logger.Log.Fatalf("unable to initiate yara engine: %s", err.Error())
	}

	logger.Log.Info("mole engine initiated successfully")

	motor.Start()
}

// ensureRoot checks whether mole is been running as root usser
func ensureRoot() {
	if uid := syscall.Getuid(); uid != 0 {
		logger.Log.Fatal("you need to be root")

	}
}
