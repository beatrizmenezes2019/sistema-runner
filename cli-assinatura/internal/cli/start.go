package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Inicia o assinador.jar no modo servidor HTTP",
	Long: `Inicia o assinador.jar como servidor HTTP em background.

Se já houver uma instância ativa (verificado via health check real),
reutiliza a existente sem iniciar um novo processo.

O estado do servidor (PID e porta) é salvo em ~/.hubsaude/assinador.state.json
para que outros comandos possam gerenciá-lo.

Exemplos:
  # Inicia na porta padrão (8080)
  assinatura start

  # Inicia em porta personalizada
  assinatura start --port 9090

  # Inicia com auto-shutdown após 30 minutos de inatividade
  assinatura start --timeout 30`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runStart()
	},
}

var (
	startPort    int
	startTimeout int
)

func init() {
	startCmd.Flags().IntVar(&startPort, "port", 0, "Porta HTTP do servidor (padrão: 8080 ou SERVER_PORT)")
	startCmd.Flags().IntVar(&startTimeout, "timeout", 0, "Minutos de inatividade antes do auto-shutdown (0 = desativado)")
	rootCmd.AddCommand(startCmd)
}

func runStart() error {
	port := startPort
	if port == 0 {
		port = portFromEnv()
	}

	// Verifica se já há instância ativa
	if existing := findActiveServer(); existing != nil {
		fmt.Printf("Servidor assinador já está ativo | porta: %d | PID: %d\n",
			existing.Port, existing.PID)
		fmt.Println("Use 'assinatura stop' para encerrar ou 'assinatura status' para detalhes.")
		return nil
	}

	fmt.Printf("Iniciando assinador.jar na porta %d...\n", port)
	if startTimeout > 0 {
		fmt.Printf("Auto-shutdown configurado: %d minuto(s) de inatividade.\n", startTimeout)
	}

	state, err := startServer(port, startTimeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[ERRO]", err)
		os.Exit(1)
	}

	fmt.Printf("Servidor assinador iniciado | porta: %d | PID: %d\n", state.Port, state.PID)
	fmt.Printf("Estado salvo em: %s\n", statePath())
	fmt.Println("Use 'assinatura stop' para encerrar.")
	return nil
}
