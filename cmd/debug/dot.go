package debug

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var dotCmd = &cobra.Command{
	Use:   "dot",
	Short: "Generates a dot version of the decision tree",
	Run:   runDotCmd,
}

func init() {
	dotCmd.Flags().String("output", "stdout", "Dot output")
	dotCmd.Flags().String("rulesDir", "", "Yara Rules directory")
	dotCmd.Flags().String("rulesIndex", "", "Yara Rules directory")

	viper.BindPFlag("debug.dot.output", dotCmd.Flags().Lookup("output"))
	viper.BindPFlag("debug.dot.rules_dir", dotCmd.Flags().Lookup("rulesDir"))
	viper.BindPFlag("debug.dot.rules_index", dotCmd.Flags().Lookup("rulesIndex"))

	debugCmd.AddCommand(dotCmd)
}

func runDotCmd(cmd *cobra.Command, args []string) {

}
