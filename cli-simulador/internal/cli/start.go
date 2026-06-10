package cli

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	// URL oficial do JAR do simulador HubSaúde.
	simuladorJarURL = "https://github.com/kyriosdata/runner/releases/download/hubsaude-validador-api-v0.1.10/hubsaude-validador-api-0.1.10-exec.jar"
	// Nome local do JAR após download.
	simuladorJarName = "hubsaude-validador-api.jar"
	// Arquivo que armazena o PID do processo em execução.
	pidFileName = "simulador.pid"
	// Porta padrão do simulador.
	defaultPort = "8080"
	// Endpoint de health check.
	healthPath = "/health"
	// Tempo máximo aguardando o simulador ficar pronto.
	healthCheckTimeout = 30 * time.Second
)

var simuladorPort string

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Inicia o simulador do HubSaúde em background",
	Long: `Inicia o simulador HubSaúde em background.

O JAR é baixado automaticamente se não estiver presente em ~/.hubsaude/.
O Java 21 é provisionado automaticamente se não estiver instalado.

Exemplo:
  simulador start
  simulador start --port 9090`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runStart()
	},
}

func init() {
	startCmd.Flags().StringVar(&simuladorPort, "port", defaultPort, "Porta em que o simulador vai escutar")
	rootCmd.AddCommand(startCmd)
}

func runStart() error {
	// 1. Verificar se já está rodando (idempotência)
	if pid, err := readPID(); err == nil {
		if isProcessAlive(pid) {
			// Verificar se está respondendo ao health check
			if isHealthy(simuladorPort) {
				fmt.Printf("[info] Simulador já está em execução (PID %d, porta %s). Reutilizando.\n", pid, simuladorPort)
				return nil
			}
			// Processo vivo mas não responde — pode estar inicializando
			fmt.Printf("[info] Simulador (PID %d) está subindo, aguardando...\n", pid)
			if waitForHealth(simuladorPort, 10*time.Second) {
				fmt.Printf("[info] Simulador pronto na porta %s.\n", simuladorPort)
				return nil
			}
			fmt.Println("[warn] Processo vivo mas simulador não respondeu ao health check. Reiniciando...")
		}
		// PID obsoleto — remover
		removePID()
	}

	// 2. Resolver JAR (baixar se necessário)
	jar, err := resolveSimuladorJar()
	if err != nil {
		return fmt.Errorf("jar do simulador: %w", err)
	}

	// 3. Resolver Java (provisionar se necessário)
	java, err := resolveOrProvisionJava()
	if err != nil {
		return fmt.Errorf("JVM: %w", err)
	}

	// 4. Iniciar processo em background
	javaArgs := []string{"-jar", jar, "--server.port=" + simuladorPort}
	logVerbose("Executando: %s %s", java, strings.Join(javaArgs, " "))

	proc := exec.Command(java, javaArgs...)
	// Redirecionar saída para arquivo de log
	logFile, err := openLogFile()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[warn] Não foi possível abrir arquivo de log: %v. Saída será descartada.\n", err)
		proc.Stdout = io.Discard
		proc.Stderr = io.Discard
	} else {
		defer logFile.Close()
		proc.Stdout = logFile
		proc.Stderr = logFile
	}

	if err := proc.Start(); err != nil {
		return fmt.Errorf("iniciar simulador: %w", err)
	}

	pid := proc.Process.Pid
	if err := writePID(pid); err != nil {
		fmt.Fprintf(os.Stderr, "[warn] Não foi possível salvar PID: %v\n", err)
	}

	fmt.Printf("[info] Simulador iniciado (PID %d). Aguardando readiness na porta %s...\n", pid, simuladorPort)

	// 5. Aguardar até estar pronto para receber requisições
	if !waitForHealth(simuladorPort, healthCheckTimeout) {
		return fmt.Errorf(
			"simulador não ficou pronto em %s na porta %s.\n"+
				"Verifique o log em: %s\n"+
				"Como resolver:\n"+
				"  - Verifique se a porta %s está disponível\n"+
				"  - Execute 'simulador status' para diagnóstico",
			healthCheckTimeout, simuladorPort, hubsaudePath("simulador.log"), simuladorPort,
		)
	}

	fmt.Printf("[info] Simulador pronto e respondendo na porta %s.\n", simuladorPort)
	return nil
}

// resolveSimuladorJar retorna o caminho para o JAR do simulador, baixando-o se necessário.
func resolveSimuladorJar() (string, error) {
	jarPath := hubsaudePath(simuladorJarName)

	if _, err := os.Stat(jarPath); err == nil {
		logVerbose("JAR do simulador encontrado: %s", jarPath)
		return jarPath, nil
	}

	// Baixar automaticamente
	fmt.Fprintf(os.Stderr, "[info] JAR do simulador não encontrado. Baixando de:\n  %s\n", simuladorJarURL)

	dir := hubsaudePath("")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("criar diretório ~/.hubsaude: %w", err)
	}

	tmpPath := jarPath + ".tmp"
	defer os.Remove(tmpPath)

	if err := downloadJarFile(tmpPath, simuladorJarURL); err != nil {
		return "", fmt.Errorf("download do JAR: %w", err)
	}

	if err := os.Rename(tmpPath, jarPath); err != nil {
		return "", fmt.Errorf("salvar JAR em %s: %w", jarPath, err)
	}

	fmt.Fprintf(os.Stderr, "[info] JAR salvo em: %s\n", jarPath)
	return jarPath, nil
}

// downloadJarFile baixa um arquivo de url para destPath.
func downloadJarFile(destPath, url string) error {
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d ao baixar %s", resp.StatusCode, url)
	}

	f, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

// writePID salva o PID em ~/.hubsaude/simulador.pid.
func writePID(pid int) error {
	pidFile := hubsaudePath(pidFileName)
	if err := os.MkdirAll(filepath.Dir(pidFile), 0755); err != nil {
		return err
	}
	return os.WriteFile(pidFile, []byte(strconv.Itoa(pid)), 0644)
}

// readPID lê o PID salvo em ~/.hubsaude/simulador.pid.
func readPID() (int, error) {
	data, err := os.ReadFile(hubsaudePath(pidFileName))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

// removePID remove o arquivo de PID.
func removePID() {
	os.Remove(hubsaudePath(pidFileName)) //nolint:errcheck
}

// openLogFile abre (ou cria) o arquivo de log do simulador.
func openLogFile() (*os.File, error) {
	logPath := hubsaudePath("simulador.log")
	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		return nil, err
	}
	return os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
}

// isHealthy verifica se o simulador está respondendo ao health check.
func isHealthy(port string) bool {
	url := fmt.Sprintf("http://localhost:%s%s", port, healthPath)
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// waitForHealth aguarda até que o simulador responda ao health check ou o timeout expire.
func waitForHealth(port string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if isHealthy(port) {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}
