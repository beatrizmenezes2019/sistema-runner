package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "assinatura",
	Short: "CLI do Sistema Runner para assinaturas digitais via HubSaúde",
	Long: `assinatura — Interface de linha de comando para criação e validação
de assinaturas digitais ICP-Brasil via assinador.jar.

Modo de operação padrão: servidor HTTP (menor latência).
O CLI inicia o servidor automaticamente se necessário.
Use --local para forçar invocação direta via java -jar.

Comandos disponíveis:
  start     Inicia o assinador.jar no modo servidor HTTP
  stop      Encerra o servidor assinador
  status    Exibe o estado do servidor
  sign      Cria uma assinatura digital
  validate  Valida uma assinatura digital
  version   Exibe versão e commit do CLI

Exemplos rápidos:
  assinatura start --port 8080 --timeout 30
  assinatura sign --bundle bundle.json --provenance prov.json \
    --config '{"PKCS12":{...}}' --cert cert.der \
    --timestamp 1751328001 --estrategia AD_RB --pid 123
  assinatura validate --jws "eyJ..." --config '{"trustStore":["abc"]}'
  assinatura stop

Localização do JAR:
  1. Flag --jar <caminho>
  2. Variável ASSINADOR_JAR
  3. ~/.hubsaude/assinador.jar
  4. ./assinador.jar`,
}

// Flags globais
var (
	jarPath  string
	useLocal bool
	verbose  bool
)

func init() {
	rootCmd.PersistentFlags().StringVar(&jarPath, "jar", "", "Caminho explícito para o assinador.jar")
	rootCmd.PersistentFlags().BoolVar(&useLocal, "local", false, "Forçar modo local (java -jar) em vez do servidor HTTP")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Exibir saída de diagnóstico detalhada")

	// Configura slog: nível INFO por padrão, DEBUG com --verbose
	cobra.OnInitialize(setupLogger)
}

// setupLogger configura o logger estruturado (slog) de acordo com a flag --verbose.
// Eventos de ciclo de vida (start, stop, health check) são emitidos via slog para stderr.
// A saída do usuário (resultado do JAR) vai para stdout e não usa slog.
func setupLogger() {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}

func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return nil
}
