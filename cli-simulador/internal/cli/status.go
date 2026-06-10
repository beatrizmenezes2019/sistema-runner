package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var statusPort string

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Verifica o estado do simulador do HubSaúde",
	Long: `Verifica se o simulador está em execução e respondendo ao health check.

Distingue entre:
  - Processo em execução E respondendo (PRONTO)
  - Processo em execução MAS não respondendo (INICIALIZANDO ou DEGRADADO)
  - Processo não encontrado (PARADO)

Exemplo:
  simulador status
  simulador status --port 9090`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runStatus()
	},
}

func init() {
	statusCmd.Flags().StringVar(&statusPort, "port", defaultPort, "Porta do simulador a verificar")
	rootCmd.AddCommand(statusCmd)
}

func runStatus() error {
	pid, err := readPID()
	if err != nil {
		fmt.Println("STATUS: PARADO")
		fmt.Println("  Nenhuma instância registrada em ~/.hubsaude/simulador.pid")
		return nil
	}

	if !isProcessAlive(pid) {
		fmt.Printf("STATUS: PARADO (PID %d não encontrado — registro obsoleto removido)\n", pid)
		removePID()
		return nil
	}

	// Processo existe — verificar readiness via health check
	healthy := isHealthy(statusPort)
	if healthy {
		fmt.Printf("STATUS: PRONTO\n")
		fmt.Printf("  PID   : %d\n", pid)
		fmt.Printf("  Porta : %s\n", statusPort)
		fmt.Printf("  Health: OK (http://localhost:%s%s)\n", statusPort, healthPath)
	} else {
		fmt.Printf("STATUS: PROCESSO EM EXECUÇÃO, MAS NÃO RESPONDE\n")
		fmt.Printf("  PID   : %d\n", pid)
		fmt.Printf("  Porta : %s\n", statusPort)
		fmt.Printf("  Health: FALHOU (http://localhost:%s%s não respondeu)\n", statusPort, healthPath)
		fmt.Println("  Dica  : O simulador pode estar ainda inicializando. Aguarde ou execute 'simulador stop' e tente novamente.")
	}

	return nil
}
