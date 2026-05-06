package cli

import (
	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate [jws_data] [config_json]",
	Short: "Valida uma assinatura digital existente",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		executeJar("VALIDATE", args)
	},
}

func init() {
	rootCmd.AddCommand(validateCmd)
}