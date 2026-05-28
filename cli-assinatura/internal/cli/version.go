package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// BuildVersion e BuildCommit são injetados em tempo de build via -ldflags.
// Ex.: go build -ldflags "-X cli.BuildVersion=v1.2.3 -X cli.BuildCommit=abc1234"
var (
	BuildVersion = "dev"
	BuildCommit  = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Exibe a versão e o commit do CLI",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("assinatura %s (commit %s)\n", BuildVersion, BuildCommit)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
