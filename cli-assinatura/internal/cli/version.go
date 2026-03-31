package cli

import (
    "fmt"
    "github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
    Use:   "version",
    Short: "Exibe a versão atual do CLI",
    Run: func(cmd *cobra.Command, args []string) {
        fmt.Println("Sistema Runner CLI - Versão: 0.1.0")
    },
}

func init() {
    rootCmd.AddCommand(versionCmd)
}