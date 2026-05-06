package cli

import (
	"fmt"
	"os"
	"os/exec"
	"github.com/spf13/cobra"
)

var signCmd = &cobra.Command{
	Use:   "sign [bundle] [provenance] [config] [cert] [time] [strategy] [pid]",
	Short: "Gera uma assinatura digital via assinador.jar",
	Args:  cobra.ExactArgs(7),
	Run: func(cmd *cobra.Command, args []string) {
		executeJar("SIGN", args)
	},
}

func init() {
	rootCmd.AddCommand(signCmd)
}

func executeJar(operation string, params []string) {
	jarPath := "assinador.jar"
	if _, err := os.Stat(jarPath); os.IsNotExist(err) {
		fmt.Printf("Erro: %s não encontrado no diretório atual.\n", jarPath)
		return
	}

	fullArgs := append([]string{"-jar", jarPath, operation}, params...)

	runCmd := exec.Command("java", fullArgs...)
	
	runCmd.Stdout = os.Stdout
	runCmd.Stderr = os.Stderr

	fmt.Printf("Executando %s via Java...\n", operation)
	if err := runCmd.Run(); err != nil {
		fmt.Printf("\nErro ao executar o assinador: %v\n", err)
	}
}