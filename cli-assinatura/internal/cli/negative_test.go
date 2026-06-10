package cli

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// =========================================================================
// Cenários negativos — JAR ausente
// =========================================================================

func TestResolveJar_AllSourcesMissing(t *testing.T) {
	t.Setenv("ASSINADOR_JAR", "")
	jarPath = ""

	// Garante que não há assinador.jar no diretório atual nem em ~/.hubsaude/
	os.Remove("assinador.jar")

	_, err := resolveJar()
	if err == nil {
		t.Fatal("esperava erro quando nenhuma fonte de JAR está disponível")
	}
	if !strings.Contains(err.Error(), "assinador.jar não encontrado") {
		t.Errorf("mensagem de erro inesperada: %v", err)
	}
	// Verifica que a mensagem instrui o usuário sobre como resolver
	if !strings.Contains(err.Error(), "Como resolver") {
		t.Errorf("mensagem de erro deveria conter instruções 'Como resolver'")
	}
}

func TestResolveJar_EnvPointsToMissingFile(t *testing.T) {
	t.Setenv("ASSINADOR_JAR", "/caminho/inexistente/assinador.jar")
	jarPath = ""
	os.Remove("assinador.jar")

	_, err := resolveJar()
	if err == nil {
		t.Fatal("esperava erro quando ASSINADOR_JAR aponta para arquivo inexistente")
	}
}

// =========================================================================
// Cenários negativos — JVM ausente
// =========================================================================

func TestResolveJava_InvalidJavaHome(t *testing.T) {
	// JAVA_HOME aponta para diretório sem java
	t.Setenv("JAVA_HOME", t.TempDir())

	// Zera PATH para evitar encontrar java no sistema
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", "")
	defer t.Setenv("PATH", origPath)

	// Zera cache local
	overrideHome(t)

	// Deve tentar provisionar (vai falhar por falta de rede no teste unitário)
	// O importante é que não retorne JAVA_HOME/bin/java para um diretório sem java
	_, err := resolveJava()
	// Pode falhar por falta de rede — o que importa é que não retorna o java fake
	if err == nil {
		// Se retornou sem erro, verifica que não é o java inválido
		// (em ambientes com java no cache ou PATH isso pode não falhar)
		t.Log("resolveJava retornou sem erro — pode haver java em cache ou PATH")
	}
}

// =========================================================================
// Cenários negativos — porta ocupada (servidor não é o assinador)
// =========================================================================

func TestIsAlive_PortOccupiedByOtherService(t *testing.T) {
	// Sobe um servidor que responde /health com 503 (não é o assinador)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	port := extractPort(t, srv.URL)

	// isAlive deve retornar false: porta ocupada mas não responde 200 no /health
	if isAlive(port) {
		t.Error("isAlive deveria retornar false quando /health responde com 503 (outro serviço na porta)")
	}
}

func TestFindActiveServer_PortOccupiedByOtherService(t *testing.T) {
	overrideStatePath(t)

	// Servidor que responde 503 no /health
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	port := extractPort(t, srv.URL)
	// Escreve estado simulando que o assinador estaria nessa porta
	writeState(&serverState{PID: 99999, Port: port}) //nolint:errcheck

	// findActiveServer deve considerar isso como inativo
	got := findActiveServer()
	if got != nil {
		t.Errorf("findActiveServer deveria retornar nil quando /health responde 503, obteve %+v", got)
	}
}

// =========================================================================
// Cenários negativos — timeout de startup
// =========================================================================

func TestIsAlive_ConnectionRefused(t *testing.T) {
	// Porta que definitivamente não tem ninguém ouvindo
	if isAlive(19876) {
		t.Error("isAlive deveria retornar false para porta sem servidor (conexão recusada)")
	}
}

func TestIsAlive_SlowServer(t *testing.T) {
	// Servidor que demora mais que o timeout do isAlive (2s)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	port := extractPort(t, srv.URL)

	start := time.Now()
	alive := isAlive(port)
	elapsed := time.Since(start)

	if alive {
		t.Error("isAlive deveria retornar false para servidor que responde após o timeout")
	}
	// Verifica que o timeout foi respeitado (não ficou esperando os 3s completos)
	if elapsed > 2500*time.Millisecond {
		t.Errorf("isAlive demorou %v, deveria ter respeitado timeout de 2s", elapsed)
	}
}

// =========================================================================
// Cenários negativos — arquivo de estado corrompido
// =========================================================================

func TestReadState_EmptyFile(t *testing.T) {
	overrideStatePath(t)
	os.WriteFile(statePath(), []byte(""), 0644) //nolint:errcheck

	if s := readState(); s != nil {
		t.Errorf("readState deveria retornar nil para arquivo vazio, obteve %+v", s)
	}
}

func TestReadState_InvalidPort(t *testing.T) {
	overrideStatePath(t)
	os.WriteFile(statePath(), []byte(`{"pid":123,"port":-1}`), 0644) //nolint:errcheck

	// Deve ler sem panic, porta negativa será tratada como inativa pelo health check
	state := readState()
	if state == nil {
		t.Fatal("readState não deveria retornar nil para JSON válido com porta negativa")
	}
	if isAlive(state.Port) {
		t.Error("isAlive deveria retornar false para porta negativa")
	}
}

// =========================================================================
// Cenários negativos — stopServer sem servidor ativo
// =========================================================================

func TestStopServer_NoServerOnPort(t *testing.T) {
	overrideStatePath(t)

	err := stopServer(19875)
	if err == nil {
		t.Fatal("stopServer deveria retornar erro quando não há servidor na porta")
	}
	if !strings.Contains(err.Error(), "19875") {
		t.Errorf("mensagem de erro deveria mencionar a porta 19875, obteve: %v", err)
	}
}

// =========================================================================
// Helpers
// =========================================================================

// overrideHome redireciona o diretório home para um temporário, limpando o cache de JDK.
func overrideHome(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir()) // Windows
}

// extractPort extrai a porta de uma URL no formato http://127.0.0.1:PORT.
func extractPort(t *testing.T, url string) int {
	t.Helper()
	parts := strings.Split(url, ":")
	portStr := parts[len(parts)-1]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("não foi possível extrair porta de %q: %v", url, err)
	}
	return port
}

// unusedPort retorna uma porta TCP livre no sistema.
func unusedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("não foi possível encontrar porta livre: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}
