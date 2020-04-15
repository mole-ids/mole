package cmd

import (
	"log"
	"syscall"

	"github.com/jpalanco/mole/pkg/engine"
	"github.com/jpalanco/mole/pkg/logger"
	"github.com/k0kubun/pp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var mitreCmd = &cobra.Command{
	Use:   "ids",
	Short: "start Mole as IDS",
	Run:   runMitreCmd,
}

func init() {
	mitreCmd.Flags().String("iface", "", "Listen on interface")
	mitreCmd.Flags().String("rulesDir", "", "Yara Rules directory")
	mitreCmd.Flags().String("rulesIndex", "", "Yara Rules directory")
	mitreCmd.Flags().Bool("pfring", true, "Enable PF Ring on the interface")
	mitreCmd.Flags().String("bpf", "", "BPF filter")
	mitreCmd.Flags().String("logTo", "", "Log to file")
	mitreCmd.Flags().String("logLevel", "info", "Log level")
	mitreCmd.Flags().StringSlice("variables", []string{}, "Varaiables value used in the rules")

	viper.BindPFlag("interface.iface", mitreCmd.Flags().Lookup("iface"))
	viper.BindPFlag("interface.pf_ring", mitreCmd.Flags().Lookup("pfring"))
	viper.BindPFlag("interface.bpf", mitreCmd.Flags().Lookup("bpf"))

	viper.BindPFlag("rules.rules_dir", mitreCmd.Flags().Lookup("rulesDir"))
	viper.BindPFlag("rules.rules_index", mitreCmd.Flags().Lookup("rulesIndex"))
	viper.BindPFlag("rules.variables", mitreCmd.Flags().Lookup("variables"))

	viper.BindPFlag("logger.log_to", mitreCmd.Flags().Lookup("logTo"))
	viper.BindPFlag("logger.log_level", mitreCmd.Flags().Lookup("logLevel"))

	RootCmd.AddCommand(mitreCmd)
}

func runMitreCmd(cmd *cobra.Command, args []string) {
	// Ensure user is root
	ensureRoot()

	logger, err := logger.New()
	if err != nil {
		log.Fatalf("unable to initiate logger: %s", err.Error())
	}

	// iface, err := interfaces.New()
	// if err != nil {
	// 	logger.Log.Fatalf("unable to initiate interfaces: %s", err.Error())
	// }

	// var ring *pfring.Ring
	// if iface.EnablePFRing() {
	// 	ring, err = iface.InitPFRing()
	// 	if err != nil {
	// 		logger.Log.Fatalf("unable to configure PF Ring: %s", err.Error())
	// 	}
	// }

	ye, err := engine.New()
	if err != nil {
		logger.Log.Fatalf("unable to initiate yara engine: %s", err.Error())
	}
	pp.Println(ye)
}

func ensureRoot() {
	logger, _ := logger.New()
	if uid := syscall.Getuid(); uid != 0 {
		if logger == nil {
			log.Fatal("you need to be root")
		} else {
			logger.Log.Fatal("you need to be root")
		}
	}
}
