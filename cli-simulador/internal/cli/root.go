package cli

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "simulador",
	Short: "CLI do Sistema Runner para integração com HubSaúde",
	Long: `Interface de linha de comando para execução e gerenciamento do simulador HubSaúde.

O simulador baixa automaticamente o JAR do HubSaúde e o Java 21 (se necessário).

Exemplos:
  simulador start           # Inicia o simulador (porta padrão 8080)
  simulador start --port 9090
  simulador status          # Verifica se está em execução
  simulador stop            # Encerra o simulador
  simulador version         # Exibe a versão`,
}

// Execute é o ponto de entrada do CLI.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Exibir saída de diagnóstico detalhada")
	cobra.OnInitialize(setupLogger)
}

// setupLogger configura o logger estruturado (slog) de acordo com a flag --verbose.
func setupLogger() {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}
