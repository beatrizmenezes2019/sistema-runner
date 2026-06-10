package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const httpTimeout = 60 * time.Second

// callSign envia POST /sign para o servidor ativo ou faz fallback para modo local.
//
// Fluxo de decisão:
//  1. Se --local foi passado → modo local (java -jar) diretamente
//  2. Verifica se há servidor ativo (health check real)
//     - Ativo → chama POST /sign via HTTP
//     - Inativo → tenta iniciar servidor, depois chama via HTTP
//     - Falha ao iniciar → fallback para modo local
func callSign(port int, params []string) error {
	if useLocal {
		return runJar("SIGN", params)
	}
	return callHTTPWithFallback(port, "/sign", buildSignBody(params), params, "SIGN")
}

// callValidate envia POST /validate para o servidor ativo ou faz fallback para modo local.
func callValidate(port int, params []string) error {
	if useLocal {
		return runJar("VALIDATE", params)
	}
	return callHTTPWithFallback(port, "/validate", buildValidateBody(params), params, "VALIDATE")
}

func callHTTPWithFallback(port int, path string, body []byte, localParams []string, op string) error {
	active := findActiveServer()

	if active == nil {
		// Nenhum servidor ativo — tenta iniciar
		if verbose {
			fmt.Fprintf(os.Stderr, "[verbose] Nenhum servidor ativo. Tentando iniciar na porta %d...\n", port)
		}
		state, err := startServer(port, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[aviso] Não foi possível iniciar o servidor: %v\n", err)
			fmt.Fprintln(os.Stderr, "[aviso] Usando modo local (java -jar).")
			return runJar(op, localParams)
		}
		active = state
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "[verbose] Usando servidor HTTP na porta %d (PID %d)\n",
			active.Port, active.PID)
	}

	return postToServer(active.Port, path, body)
}

func postToServer(port int, path string, body []byte) error {
	url := serverURL(port) + path
	client := &http.Client{Timeout: httpTimeout}

	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf(
			"falha ao conectar ao servidor na porta %d: %w\n"+
				"Como resolver:\n"+
				"  - Verifique se o servidor está ativo: assinatura status\n"+
				"  - Inicie o servidor: assinatura start\n"+
				"  - Ou use modo local: assinatura sign --local ...",
			port, err,
		)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("falha ao ler resposta do servidor: %w", err)
	}

	fmt.Print(string(respBody))

	// HTTP 422 = OperationOutcome com severity=fatal
	if resp.StatusCode == http.StatusUnprocessableEntity {
		os.Exit(1)
	}
	if resp.StatusCode >= 400 {
		os.Exit(1)
	}
	return nil
}

func buildSignBody(params []string) []byte {
	// params = [bundle, provenance, configCripto, cert, timestamp, estrategia, pid]
	m := map[string]string{
		"bundle":      safeGet(params, 0),
		"provenance":  safeGet(params, 1),
		"configCripto": safeGet(params, 2),
		"cert":        safeGet(params, 3),
		"timestamp":   safeGet(params, 4),
		"estrategia":  safeGet(params, 5),
		"pid":         safeGet(params, 6),
	}
	b, _ := json.Marshal(m)
	return b
}

func buildValidateBody(params []string) []byte {
	// params = [jws, configJson]
	m := map[string]string{
		"jws":        safeGet(params, 0),
		"configJson": safeGet(params, 1),
	}
	b, _ := json.Marshal(m)
	return b
}

func safeGet(s []string, i int) string {
	if i < len(s) {
		return s[i]
	}
	return ""
}
