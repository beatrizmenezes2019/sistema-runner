package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Exibe o estado atual do servidor assinador",
	Long: `Consulta se o servidor assinador está em execução.

A verificação é feita em duas etapas:
  1. Lê o estado salvo em ~/.hubsaude/assinador.state.json
  2. Confirma com um health check HTTP real (GET /health)

Exemplos:
  assinatura status
  assinatura status --port 9090`,
	Run: func(cmd *cobra.Command, args []string) {
		port := statusPort
		if port == 0 {
			if state := readState(); state != nil {
				port = state.Port
			} else {
				port = portFromEnv()
			}
		}
		fmt.Println(serverStatus(port))
	},
}

var statusPort int

func init() {
	statusCmd.Flags().IntVar(&statusPort, "port", 0, "Porta a verificar (padrão: porta registrada ou 8080)")
	rootCmd.AddCommand(statusCmd)
}
