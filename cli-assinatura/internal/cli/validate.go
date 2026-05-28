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

O parâmetro --jws aceita dois formatos:
  - JWS compacto:       eyJhbGciOiJSUzI1NiJ9.cGF5bG9hZA.c2lnbmF0dXJl
  - OperationOutcome:   JSON com o JWS em issue[0].diagnostics

Exemplos:
  # Validar com JWS compacto
  assinatura validate \
    --jws "eyJhbGciOiJSUzI1NiJ9.cGF5bG9hZA.c2lnbmF0dXJl" \
    --config '{"trustStore":["abc123def456"]}'

  # Validar passando o OperationOutcome gerado pelo comando sign
  assinatura validate \
    --jws "$(cat resultado-sign.json)" \
    --config '{"trustStore":["abc123def456"],"revocationPolicy":"soft-fail"}'`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runValidate()
	},
}

var (
	validateJws    string
	validateConfig string
)

func init() {
	validateCmd.Flags().StringVar(&validateJws, "jws", "", "JWS compacto ou OperationOutcome JSON com o JWS (obrigatório)")
	validateCmd.Flags().StringVar(&validateConfig, "config", "", "JSON de configuração de validação com trustStore (obrigatório)")

	_ = validateCmd.MarkFlagRequired("jws")
	_ = validateCmd.MarkFlagRequired("config")

	rootCmd.AddCommand(validateCmd)
}

func runValidate() error {
	params := []string{validateJws, validateConfig}

	if err := runJar("VALIDATE", params); err != nil {
		fmt.Fprintln(os.Stderr, "[ERRO]", err)
		os.Exit(1)
	}
	return nil
}
