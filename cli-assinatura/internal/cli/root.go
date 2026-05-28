package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "assinatura",
	Short: "CLI do Sistema Runner para assinaturas digitais via HubSaúde",
	Long: `assinatura — Interface de linha de comando para criação e validação
de assinaturas digitais ICP-Brasil via assinador.jar.

Exemplos de uso:
  # Assinar um bundle FHIR
  assinatura sign \
    --bundle bundle.json \
    --provenance provenance.json \
    --config '{"PKCS12":{"Conteúdo":"base64...","Senha":"1234","Alias":"meu-cert"}}' \
    --cert certificado.der \
    --timestamp 1751328001 \
    --estrategia AD_RB \
    --pid 12345678901

  # Validar uma assinatura
  assinatura validate \
    --jws "eyJhbGciOiJSUzI1NiJ9.cGF5bG9hZA.c2lnbmF0dXJl" \
    --config '{"trustStore":["abc123def456"]}'

  # Modo local explícito (sem servidor HTTP)
  assinatura sign --local --bundle bundle.json ...

Localização do JAR:
  O assinador.jar é procurado na seguinte ordem:
    1. Flag --jar <caminho>
    2. Variável de ambiente ASSINADOR_JAR
    3. ~/.hubsaude/assinador.jar
    4. ./assinador.jar (diretório atual)`,
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
}

func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return nil
}
