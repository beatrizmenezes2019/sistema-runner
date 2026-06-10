package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Encerra o assinador.jar em execução",
	Long: `Encerra o servidor assinador na porta especificada (ou na padrão).

O encerramento é feito em duas etapas:
  1. Requisição POST /shutdown para encerramento controlado
  2. SIGTERM via PID registrado, caso o endpoint não responda

Exemplos:
  # Encerra o servidor na porta padrão
  assinatura stop

  # Encerra um servidor em porta específica
  assinatura stop --port 9090`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runStop()
	},
}

var stopPort int

func init() {
	stopCmd.Flags().IntVar(&stopPort, "port", 0, "Porta HTTP do servidor a encerrar (padrão: 8080 ou SERVER_PORT)")
	rootCmd.AddCommand(stopCmd)
}

func runStop() error {
	port := stopPort
	if port == 0 {
		// Tenta usar a porta do estado salvo
		if state := readState(); state != nil {
			port = state.Port
		} else {
			port = portFromEnv()
		}
	}

	fmt.Printf("Encerrando servidor assinador na porta %d...\n", port)

	if err := stopServer(port); err != nil {
		fmt.Fprintln(os.Stderr, "[ERRO]", err)
		os.Exit(1)
	}

	fmt.Printf("Servidor assinador encerrado (porta %d).\n", port)
	return nil
}
