package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// -------------------------------------------------------------------------
// resolveJar
// -------------------------------------------------------------------------

func TestResolveJar_EnvVar(t *testing.T) {
	f := tempFile(t, "assinador.jar")

	t.Setenv("ASSINADOR_JAR", f)
	jarPath = "" // garante que flag não interfere

	got, err := resolveJar()
	if err != nil {
		t.Fatalf("esperava caminho, obteve erro: %v", err)
	}
	if got != f {
		t.Errorf("esperava %q, obteve %q", f, got)
	}
}

func TestResolveJar_Flag(t *testing.T) {
	f := tempFile(t, "assinador.jar")

	t.Setenv("ASSINADOR_JAR", "") // zera env para não interferir
	jarPath = f

	got, err := resolveJar()
	if err != nil {
		t.Fatalf("esperava caminho, obteve erro: %v", err)
	}
	if got != f {
		t.Errorf("esperava %q, obteve %q", f, got)
	}

	t.Cleanup(func() { jarPath = "" })
}

func TestResolveJar_CurrentDir(t *testing.T) {
	// Cria assinador.jar no diretório de trabalho atual
	cwd, _ := os.Getwd()
	target := filepath.Join(cwd, "assinador.jar")
	if err := os.WriteFile(target, []byte("fake"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(target) })

	t.Setenv("ASSINADOR_JAR", "")
	jarPath = ""

	got, err := resolveJar()
	if err != nil {
		t.Fatalf("esperava caminho, obteve erro: %v", err)
	}
	if got != "assinador.jar" {
		t.Errorf("esperava %q, obteve %q", "assinador.jar", got)
	}
}

func TestResolveJar_NotFound(t *testing.T) {
	t.Setenv("ASSINADOR_JAR", "")
	jarPath = ""

	// Garante que não há assinador.jar no diretório atual
	os.Remove("assinador.jar")

	_, err := resolveJar()
	if err == nil {
		t.Fatal("esperava erro quando JAR não existe, obteve nil")
	}
}

// -------------------------------------------------------------------------
// resolveJava
// -------------------------------------------------------------------------

func TestResolveJava_JavaHome(t *testing.T) {
	// Cria um "java" fake dentro de um diretório temporário simulando JAVA_HOME
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	os.MkdirAll(binDir, 0755)

	javaExe := filepath.Join(binDir, javaBinary())
	os.WriteFile(javaExe, []byte("#!/bin/sh\necho java"), 0755)

	t.Setenv("JAVA_HOME", dir)

	got, err := resolveJava()
	if err != nil {
		t.Fatalf("esperava caminho, obteve erro: %v", err)
	}
	if got != javaExe {
		t.Errorf("esperava %q, obteve %q", javaExe, got)
	}
}

// -------------------------------------------------------------------------
// helpers
// -------------------------------------------------------------------------

func tempFile(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("fake"), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
