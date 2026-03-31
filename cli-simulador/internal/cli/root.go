package cli

import (
    "github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
    Use:   "simulador",
    Short: "CLI do Sistema Runner para integração com HubSaúde",
    Long:  `Interface de linha de comando para execução e gerenciamento de do simulador HubSaude.`,
}

func Execute() error {
    return rootCmd.Execute() 
}