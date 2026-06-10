package cli

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

var verbose bool

// isProcessAlive verifica se o processo com o dado PID está em execução.
// No Windows usa `tasklist`; no Unix usa `kill -0 <pid>`.
func isProcessAlive(pid int) bool {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("tasklist", "/NH", "/FI",
			fmt.Sprintf("PID eq %d", pid)).Output()
		if err != nil {
			return false
		}
		return strings.Contains(string(out), strconv.Itoa(pid))
	default:
		// Unix: kill -0 não envia sinal, apenas verifica se o processo existe.
		err := exec.Command("kill", "-0", strconv.Itoa(pid)).Run()
		return err == nil
	}
}

// hubsaudePath retorna o caminho completo dentro de ~/.hubsaude/.
func hubsaudePath(filename string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".hubsaude", filename)
}

// javaBinary retorna o nome do executável java para o OS atual.
func javaBinary() string {
	if runtime.GOOS == "windows" {
		return "java.exe"
	}
	return "java"
}

// logVerbose emite mensagem de diagnóstico via slog.Debug.
// Mantido por compatibilidade com código existente; prefira slog.Debug diretamente.
func logVerbose(format string, args ...any) {
	slog.Debug(fmt.Sprintf(format, args...))
}
