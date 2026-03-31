package cli

import (
    "github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
    Use:   "assinatura",
    Short: "CLI do Sistema Runner para integração com HubSaúde",
    Long:  `Interface de linha de comando para execução e gerenciamento de assinaturas digitais via Java.`,
}

func Execute() error {
    return rootCmd.Execute() // Se isso não for retornado/chamado, nada acontece
}