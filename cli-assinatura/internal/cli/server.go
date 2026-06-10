package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"
)

const (
	defaultPort    = 8080
	healthPath     = "/health"
	shutdownPath   = "/shutdown"
	stateFileName  = "assinador.state.json"
	startupTimeout = 30 * time.Second
	healthInterval = 500 * time.Millisecond
)

// serverState é o JSON salvo em ~/.hubsaude/assinador.state.json.
type serverState struct {
	PID  int `json:"pid"`
	Port int `json:"port"`
}

// statePath retorna o caminho completo do arquivo de estado.
func statePath() string {
	return hubsaudePath(stateFileName)
}

// readState lê o estado salvo. Retorna nil se não existir.
func readState() *serverState {
	data, err := os.ReadFile(statePath())
	if err != nil {
		return nil
	}
	var s serverState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil
	}
	return &s
}

// writeState persiste o estado em ~/.hubsaude/.
func writeState(s *serverState) error {
	dir := filepath.Dir(statePath())
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("não foi possível criar %s: %w", dir, err)
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(statePath(), data, 0644)
}

// clearState remove o arquivo de estado.
func clearState() {
	os.Remove(statePath())
}

// serverURL monta a URL base do servidor.
func serverURL(port int) string {
	return fmt.Sprintf("http://localhost:%d", port)
}

// isAlive verifica se o servidor está respondendo ao health check.
// Não usa apenas "porta ocupada" — faz um GET /health real.
func isAlive(port int) bool {
	url := serverURL(port) + healthPath
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// findActiveServer verifica o estado salvo e confirma via health check.
// Retorna nil se não houver instância ativa.
func findActiveServer() *serverState {
	state := readState()
	if state == nil {
		return nil
	}
	if !isAlive(state.Port) {
		// Processo registrado não responde — limpa estado obsoleto
		clearState()
		return nil
	}
	return state
}

// startServer inicia o assinador.jar em background como servidor HTTP.
// Aguarda até startupTimeout para confirmar que está pronto (health check).
func startServer(port, timeoutMinutes int) (*serverState, error) {
	jar, err := resolveJar()
	if err != nil {
		return nil, fmt.Errorf("assinador.jar: %w", err)
	}
	java, err := resolveJava()
	if err != nil {
		return nil, fmt.Errorf("JVM: %w", err)
	}

	args := []string{
		"-jar", jar,
		fmt.Sprintf("--server.port=%d", port),
	}
	if timeoutMinutes > 0 {
		args = append(args, "-e", fmt.Sprintf("ASSINADOR_TIMEOUT_MINUTOS=%d", timeoutMinutes))
	}

	cmd := exec.Command(java, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil

	// Desanexa o processo do terminal para que continue rodando após o CLI sair.
	// A implementação varia por plataforma (ver server_sysattr_unix.go / server_sysattr_windows.go).
	detachProcess(cmd)

	// Propaga ASSINADOR_TIMEOUT_MINUTOS via env se definido
	if timeoutMinutes > 0 {
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("ASSINADOR_TIMEOUT_MINUTOS=%d", timeoutMinutes))
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("falha ao iniciar o assinador.jar: %w", err)
	}

	pid := cmd.Process.Pid
	state := &serverState{PID: pid, Port: port}

	if err := writeState(state); err != nil {
		// Não fatal — servidor subiu, mas não conseguimos salvar o estado
		fmt.Fprintf(os.Stderr, "[aviso] Não foi possível salvar estado em %s: %v\n", statePath(), err)
	}

	// Aguarda o servidor estar pronto
	deadline := time.Now().Add(startupTimeout)
	for time.Now().Before(deadline) {
		if isAlive(port) {
			return state, nil
		}
		time.Sleep(healthInterval)
	}

	// Timeout: encerra o processo que não ficou pronto
	cmd.Process.Kill()
	clearState()
	return nil, fmt.Errorf(
		"assinador.jar não ficou pronto em %s na porta %d.\n"+
			"Como resolver:\n"+
			"  - Verifique se a porta %d está disponível (lsof -i :%d)\n"+
			"  - Use --port para escolher outra porta\n"+
			"  - Rode com --verbose para ver a saída do servidor",
		startupTimeout, port, port, port,
	)
}

// stopServer encerra o servidor na porta especificada.
// Tenta primeiro o endpoint /shutdown; se falhar, envia SIGTERM.
func stopServer(port int) error {
	if !isAlive(port) {
		// Limpa estado se existir
		state := readState()
		if state != nil && state.Port == port {
			clearState()
		}
		return fmt.Errorf("nenhum servidor assinador encontrado na porta %d", port)
	}

	// Tenta shutdown via endpoint
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(serverURL(port)+shutdownPath, "application/json", nil)
	if err == nil {
		defer resp.Body.Close()
	}

	// Aguarda o servidor encerrar (até 10s)
	for i := 0; i < 20; i++ {
		time.Sleep(500 * time.Millisecond)
		if !isAlive(port) {
			clearState()
			return nil
		}
	}

	// Fallback: SIGTERM via PID registrado
	state := readState()
	if state != nil && state.PID > 0 {
		proc, err := os.FindProcess(state.PID)
		if err == nil {
			if runtime.GOOS == "windows" {
				proc.Kill()
			} else {
				proc.Signal(syscall.SIGTERM)
			}
		}
	}

	clearState()
	return nil
}

// serverStatus retorna uma string descrevendo o estado atual do servidor.
func serverStatus(port int) string {
	state := readState()

	if state == nil {
		if isAlive(port) {
			return fmt.Sprintf("ATIVO na porta %d (processo externo, sem registro local)", port)
		}
		return fmt.Sprintf("INATIVO na porta %d (sem registro em %s)", port, statePath())
	}

	if isAlive(state.Port) {
		return fmt.Sprintf("ATIVO | porta: %d | PID: %d | estado: %s",
			state.Port, state.PID, statePath())
	}

	clearState()
	return fmt.Sprintf("INATIVO (processo registrado PID %d não responde — estado limpo)", state.PID)
}

// portFromEnv lê SERVER_PORT do ambiente, com fallback para defaultPort.
func portFromEnv() int {
	if v := os.Getenv("SERVER_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			return p
		}
	}
	return defaultPort
}
