package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// -------------------------------------------------------------------------
// readState / writeState / clearState
// -------------------------------------------------------------------------

func TestStateRoundtrip(t *testing.T) {
	// Redireciona statePath para um arquivo temporário
	overrideStatePath(t)

	want := &serverState{PID: 12345, Port: 9090}
	if err := writeState(want); err != nil {
		t.Fatalf("writeState: %v", err)
	}

	got := readState()
	if got == nil {
		t.Fatal("readState retornou nil após writeState")
	}
	if got.PID != want.PID || got.Port != want.Port {
		t.Errorf("esperava %+v, obteve %+v", want, got)
	}
}

func TestReadState_Missing(t *testing.T) {
	overrideStatePath(t)
	os.Remove(statePath())

	if s := readState(); s != nil {
		t.Errorf("esperava nil para arquivo inexistente, obteve %+v", s)
	}
}

func TestClearState(t *testing.T) {
	overrideStatePath(t)

	writeState(&serverState{PID: 1, Port: 8080})
	clearState()

	if _, err := os.Stat(statePath()); !os.IsNotExist(err) {
		t.Error("clearState não removeu o arquivo de estado")
	}
}

func TestReadState_CorruptJson(t *testing.T) {
	overrideStatePath(t)
	os.WriteFile(statePath(), []byte("{ isso nao e json"), 0644)

	if s := readState(); s != nil {
		t.Errorf("esperava nil para JSON corrompido, obteve %+v", s)
	}
}

// -------------------------------------------------------------------------
// isAlive
// -------------------------------------------------------------------------

func TestIsAlive_ServerUp(t *testing.T) {
	srv := fakeHealthServer(t, http.StatusOK)
	port := serverPort(t, srv.URL)

	if !isAlive(port) {
		t.Error("isAlive deveria retornar true para servidor ativo")
	}
}

func TestIsAlive_ServerDown(t *testing.T) {
	// Porta que não tem ninguém ouvindo
	if isAlive(19999) {
		t.Error("isAlive deveria retornar false para porta fechada")
	}
}

func TestIsAlive_Non200Response(t *testing.T) {
	srv := fakeHealthServer(t, http.StatusServiceUnavailable)
	port := serverPort(t, srv.URL)

	if isAlive(port) {
		t.Error("isAlive deveria retornar false para resposta não-200")
	}
}

// -------------------------------------------------------------------------
// findActiveServer
// -------------------------------------------------------------------------

func TestFindActiveServer_ActiveInstance(t *testing.T) {
	overrideStatePath(t)
	srv := fakeHealthServer(t, http.StatusOK)
	port := serverPort(t, srv.URL)

	writeState(&serverState{PID: 99999, Port: port})

	got := findActiveServer()
	if got == nil {
		t.Fatal("findActiveServer retornou nil para servidor ativo")
	}
	if got.Port != port {
		t.Errorf("esperava porta %d, obteve %d", port, got.Port)
	}
}

func TestFindActiveServer_StaleState(t *testing.T) {
	overrideStatePath(t)

	// Salva estado com porta que não tem servidor
	writeState(&serverState{PID: 99999, Port: 19998})

	got := findActiveServer()
	if got != nil {
		t.Errorf("findActiveServer deveria retornar nil para estado obsoleto, obteve %+v", got)
	}

	// Estado deve ter sido limpo
	if readState() != nil {
		t.Error("estado obsoleto não foi limpo")
	}
}

func TestFindActiveServer_NoState(t *testing.T) {
	overrideStatePath(t)
	os.Remove(statePath())

	if got := findActiveServer(); got != nil {
		t.Errorf("findActiveServer deveria retornar nil sem estado, obteve %+v", got)
	}
}

// -------------------------------------------------------------------------
// serverStatus
// -------------------------------------------------------------------------

func TestServerStatus_Active(t *testing.T) {
	overrideStatePath(t)
	srv := fakeHealthServer(t, http.StatusOK)
	port := serverPort(t, srv.URL)
	writeState(&serverState{PID: 42, Port: port})

	status := serverStatus(port)
	if !strings.Contains(status, "ATIVO") {
		t.Errorf("esperava 'ATIVO' no status, obteve: %s", status)
	}
}

func TestServerStatus_Inactive(t *testing.T) {
	overrideStatePath(t)
	os.Remove(statePath())

	status := serverStatus(19997)
	if !strings.Contains(status, "INATIVO") {
		t.Errorf("esperava 'INATIVO' no status, obteve: %s", status)
	}
}

// -------------------------------------------------------------------------
// serverURL / portFromEnv
// -------------------------------------------------------------------------

func TestServerURL(t *testing.T) {
	got := serverURL(8080)
	if got != "http://localhost:8080" {
		t.Errorf("serverURL(8080) = %q, esperava %q", got, "http://localhost:8080")
	}
}

func TestPortFromEnv_Default(t *testing.T) {
	t.Setenv("SERVER_PORT", "")
	if p := portFromEnv(); p != defaultPort {
		t.Errorf("esperava %d, obteve %d", defaultPort, p)
	}
}

func TestPortFromEnv_Custom(t *testing.T) {
	t.Setenv("SERVER_PORT", "9191")
	if p := portFromEnv(); p != 9191 {
		t.Errorf("esperava 9191, obteve %d", p)
	}
}

// -------------------------------------------------------------------------
// buildSignBody / buildValidateBody
// -------------------------------------------------------------------------

func TestBuildSignBody(t *testing.T) {
	params := []string{"bundle.json", "prov.json", "{}", "cert.der", "1751328001", "AD_RB", "pid-1"}
	body := buildSignBody(params)

	var m map[string]string
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("buildSignBody gerou JSON inválido: %v", err)
	}

	checks := map[string]string{
		"bundle": "bundle.json", "provenance": "prov.json",
		"configCripto": "{}", "cert": "cert.der",
		"timestamp": "1751328001", "estrategia": "AD_RB", "pid": "pid-1",
	}
	for k, want := range checks {
		if got := m[k]; got != want {
			t.Errorf("campo %q: esperava %q, obteve %q", k, want, got)
		}
	}
}

func TestBuildValidateBody(t *testing.T) {
	params := []string{"eyJ.cGF5.c2ln", `{"trustStore":[]}`}
	body := buildValidateBody(params)

	var m map[string]string
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("buildValidateBody gerou JSON inválido: %v", err)
	}
	if m["jws"] != params[0] {
		t.Errorf("jws: esperava %q, obteve %q", params[0], m["jws"])
	}
	if m["configJson"] != params[1] {
		t.Errorf("configJson: esperava %q, obteve %q", params[1], m["configJson"])
	}
}

// -------------------------------------------------------------------------
// Helpers de teste
// -------------------------------------------------------------------------

// overrideStatePath redireciona statePath() para um arquivo dentro de t.TempDir().
// Cria também o diretório .hubsaude para que os.WriteFile funcione diretamente.
func overrideStatePath(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)        // hubsaudePath usa os.UserHomeDir() — Linux/macOS
	t.Setenv("USERPROFILE", dir) // Windows
	if err := os.MkdirAll(filepath.Join(dir, ".hubsaude"), 0755); err != nil {
		t.Fatalf("overrideStatePath: não foi possível criar .hubsaude: %v", err)
	}
}

// fakeHealthServer sobe um servidor HTTP que responde ao /health com o código dado.
func fakeHealthServer(t *testing.T, statusCode int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == healthPath {
			w.WriteHeader(statusCode)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// serverPort extrai a porta de uma URL httptest (ex.: http://127.0.0.1:54321).
func serverPort(t *testing.T, url string) int {
	t.Helper()
	parts := strings.Split(url, ":")
	portStr := parts[len(parts)-1]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("não foi possível extrair porta de %q: %v", url, err)
	}
	return port
}
