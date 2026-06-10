package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Valida uma assinatura digital via assinador.jar",
	Long: `Valida uma assinatura digital ICP-Brasil.

Por padrão, usa o modo servidor HTTP (menor latência).
Se não houver servidor ativo, tenta iniciá-lo automaticamente.
Use --local para forçar invocação direta via java -jar.

O parâmetro --jws aceita dois formatos:
  - JWS compacto:       eyJhbGciOiJSUzI1NiJ9.cGF5bG9hZA.c2lnbmF0dXJl
  - OperationOutcome:   JSON com o JWS em issue[0].diagnostics

Exemplos:
  # Modo servidor (padrão)
  assinatura validate \
    --jws "eyJhbGciOiJSUzI1NiJ9.cGF5bG9hZA.c2lnbmF0dXJl" \
    --config '{"trustStore":["abc123def456"]}'

  # Passando o OperationOutcome gerado pelo sign
  assinatura validate \
    --jws "$(cat resultado-sign.json)" \
    --config '{"trustStore":["abc123def456"],"revocationPolicy":"soft-fail"}'

  # Modo local explícito
  assinatura validate --local --jws "eyJ..." --config '{"trustStore":[]}'`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runValidate()
	},
}

var (
	validateJws    string
	validateConfig string
	validatePort   int
)

func init() {
	validateCmd.Flags().StringVar(&validateJws, "jws", "", "JWS compacto ou OperationOutcome JSON com o JWS (obrigatório)")
	validateCmd.Flags().StringVar(&validateConfig, "config", "", "JSON de configuração de validação com trustStore (obrigatório)")
	validateCmd.Flags().IntVar(&validatePort, "port", 0, "Porta do servidor HTTP (padrão: 8080 ou SERVER_PORT)")

	_ = validateCmd.MarkFlagRequired("jws")
	_ = validateCmd.MarkFlagRequired("config")

	rootCmd.AddCommand(validateCmd)
}

func runValidate() error {
	params := []string{validateJws, validateConfig}

	port := validatePort
	if port == 0 {
		port = portFromEnv()
	}

	if err := callValidate(port, params); err != nil {
		fmt.Fprintln(os.Stderr, "[ERRO]", err)
		os.Exit(1)
	}
	return nil
}
