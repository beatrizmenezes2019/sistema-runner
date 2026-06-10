package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Encerra o simulador do HubSaúde",
	Long: `Encerra o simulador do HubSaúde que está rodando em background.

O PID do processo é lido de ~/.hubsaude/simulador.pid.

Exemplo:
  simulador stop`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runStop()
	},
}

func init() {
	rootCmd.AddCommand(stopCmd)
}

func runStop() error {
	pid, err := readPID()
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("[info] Nenhuma instância do simulador registrada.")
			return nil
		}
		return fmt.Errorf("ler PID: %w", err)
	}

	if !isProcessAlive(pid) {
		fmt.Printf("[info] Processo %d não está em execução. Removendo registro...\n", pid)
		removePID()
		return nil
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("encontrar processo %d: %w", pid, err)
	}

	if err := proc.Kill(); err != nil {
		return fmt.Errorf("encerrar processo %d: %w\nTente: kill -9 %d", pid, err, pid)
	}

	removePID()
	fmt.Printf("[info] Simulador (PID %d) encerrado com sucesso.\n", pid)
	return nil
}
