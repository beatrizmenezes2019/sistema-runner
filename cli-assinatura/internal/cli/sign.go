package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Cria uma assinatura digital via assinador.jar",
	Long: `Cria uma assinatura digital ICP-Brasil para um bundle FHIR.

Exemplos:
  # Com certificado em PKCS12
  assinatura sign \
    --bundle bundle.json \
    --provenance provenance.json \
    --config '{"PKCS12":{"Conteúdo":"base64...","Senha":"1234","Alias":"meu-cert"}}' \
    --cert certificado.der \
    --timestamp 1751328001 \
    --estrategia AD_RB \
    --pid 12345678901

  # Com token de hardware (PKCS11)
  assinatura sign \
    --bundle bundle.json \
    --provenance provenance.json \
    --config '{"TOKEN":{"PIN":"1234","Identificador":"alias","slotId":0},"middlewareCrypto":{"Biblioteca":{"Caminho":"/usr/lib/libpkcs11.so"}}}' \
    --cert certificado.der \
    --timestamp 1751328001 \
    --estrategia AD_RT \
    --pid 12345678901`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSign()
	},
}

var (
	signBundle     string
	signProvenance string
	signConfig     string
	signCert       string
	signTimestamp  string
	signEstrategia string
	signPid        string
)

func init() {
	signCmd.Flags().StringVar(&signBundle, "bundle", "", "Caminho para o arquivo Bundle FHIR (obrigatório)")
	signCmd.Flags().StringVar(&signProvenance, "provenance", "", "Caminho para o arquivo Provenance FHIR (obrigatório)")
	signCmd.Flags().StringVar(&signConfig, "config", "", "JSON com material criptográfico PKCS12 ou TOKEN (obrigatório)")
	signCmd.Flags().StringVar(&signCert, "cert", "", "Caminho para o arquivo de certificado .der (obrigatório)")
	signCmd.Flags().StringVar(&signTimestamp, "timestamp", "", "Timestamp Unix em segundos (obrigatório)")
	signCmd.Flags().StringVar(&signEstrategia, "estrategia", "", "Estratégia de assinatura, ex.: AD_RB ou AD_RT (obrigatório)")
	signCmd.Flags().StringVar(&signPid, "pid", "", "Identificador do assinante (obrigatório)")

	_ = signCmd.MarkFlagRequired("bundle")
	_ = signCmd.MarkFlagRequired("provenance")
	_ = signCmd.MarkFlagRequired("config")
	_ = signCmd.MarkFlagRequired("cert")
	_ = signCmd.MarkFlagRequired("timestamp")
	_ = signCmd.MarkFlagRequired("estrategia")
	_ = signCmd.MarkFlagRequired("pid")

	rootCmd.AddCommand(signCmd)
}

func runSign() error {
	params := []string{
		signBundle,
		signProvenance,
		signConfig,
		signCert,
		signTimestamp,
		signEstrategia,
		signPid,
	}

	if err := runJar("SIGN", params); err != nil {
		fmt.Fprintln(os.Stderr, "[ERRO]", err)
		os.Exit(1)
	}
	return nil
}
