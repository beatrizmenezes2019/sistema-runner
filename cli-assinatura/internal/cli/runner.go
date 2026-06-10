package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// resolveJar retorna o caminho para o assinador.jar, buscando nas seguintes fontes (em ordem):
//  1. Flag --jar da linha de comando
//  2. Variável de ambiente ASSINADOR_JAR
//  3. ~/.hubsaude/assinador.jar
//  4. ./assinador.jar (diretório de trabalho atual)
func resolveJar() (string, error) {
	candidates := []struct {
		source string
		path   string
	}{
		{"--jar flag", jarPath},
		{"variável ASSINADOR_JAR", os.Getenv("ASSINADOR_JAR")},
		{"~/.hubsaude/assinador.jar", hubsaudePath("assinador.jar")},
		{"./assinador.jar", "assinador.jar"},
	}

	for _, c := range candidates {
		if c.path == "" {
			continue
		}
		if _, err := os.Stat(c.path); err == nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "[verbose] assinador.jar encontrado via %s: %s\n", c.source, c.path)
			}
			return c.path, nil
		}
	}

	return "", fmt.Errorf(
		"assinador.jar não encontrado.\n" +
			"Como resolver:\n" +
			"  1. Use a flag --jar <caminho>\n" +
			"  2. Defina a variável de ambiente ASSINADOR_JAR=<caminho>\n" +
			"  3. Coloque o arquivo em ~/.hubsaude/assinador.jar\n" +
			"  4. Coloque o arquivo no diretório atual como assinador.jar",
	)
}

// resolveJava retorna o executável `java` disponível no sistema.
// Se java não estiver instalado, provisiona automaticamente o JDK 21 Temurin.
func resolveJava() (string, error) {
	return resolveOrProvisionJava()
}

// runJar invoca o assinador.jar com os argumentos fornecidos e imprime o resultado.
// stdout do JAR vai para stdout do processo; stderr do JAR vai para stderr.
// Exit codes: 0=sucesso, 1=erro de negócio (OperationOutcome fatal), 2=erro de parâmetros.
func runJar(operation string, params []string) error {
	jar, err := resolveJar()
	if err != nil {
		return fmt.Errorf("assinador.jar: %w", err)
	}

	java, err := resolveJava()
	if err != nil {
		return fmt.Errorf("JVM: %w", err)
	}

	allArgs := append([]string{"-jar", jar, operation}, params...)

	if verbose {
		fmt.Fprintf(os.Stderr, "[verbose] Executando: %s %s\n", java, strings.Join(allArgs, " "))
	}

	cmd := exec.Command(java, allArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("falha ao executar o assinador: %w", err)
	}
	return nil
}

// hubsaudePath retorna o caminho completo dentro de ~/.hubsaude/.
func hubsaudePath(filename string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".hubsaude", filename)
}

func javaBinary() string {
	if runtime.GOOS == "windows" {
		return "java.exe"
	}
	return "java"
}
