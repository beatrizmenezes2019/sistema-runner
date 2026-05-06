package cli

import (
	"fmt"
	"os"
	"os/exec"
	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Inicia o simulador do HubSaúde em background",
	Run: func(cmd *cobra.Command, args []string) {
		jarPath := "simulador.jar"
		
		runCmd := exec.Command("java", "-jar", jarPath)
		
		if err := runCmd.Start(); err != nil {
			fmt.Printf("Erro ao iniciar simulador: %v\n", err)
			return
		}

		fmt.Printf("Simulador iniciado com sucesso! PID: %d\n", runCmd.Process.Pid)
		fmt.Println("Use 'simulador stop' para encerrar.")
		
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
}