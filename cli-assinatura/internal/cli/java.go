package cli

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const jdkVersion = "21"

// resolveOrProvisionJava retorna o executável `java` disponível no sistema.
// Busca nas seguintes fontes (em ordem):
//  1. JAVA_HOME/bin/java
//  2. java no PATH
//  3. ~/.hubsaude/jdk/bin/java (provisionado anteriormente)
//  4. Se não encontrado: baixa JDK 21 Temurin e instala em ~/.hubsaude/jdk/
func resolveOrProvisionJava() (string, error) {
	// 1. JAVA_HOME
	if jh := os.Getenv("JAVA_HOME"); jh != "" {
		candidate := filepath.Join(jh, "bin", javaBinary())
		if _, err := os.Stat(candidate); err == nil {
			logVerbose("java encontrado via JAVA_HOME: %s", candidate)
			return candidate, nil
		}
	}

	// 2. PATH
	if path, err := exec.LookPath(javaBinary()); err == nil {
		logVerbose("java encontrado no PATH: %s", path)
		return path, nil
	}

	// 3. Cache local ~/.hubsaude/jdk/
	cached := hubsaudePath(filepath.Join("jdk", "bin", javaBinary()))
	if _, err := os.Stat(cached); err == nil {
		logVerbose("java encontrado em cache local: %s", cached)
		return cached, nil
	}

	// 4. Provisionar automaticamente
	fmt.Fprintln(os.Stderr, "[info] Java não encontrado. Baixando JDK 21 (Temurin) automaticamente...")
	javaPath, err := provisionJDK()
	if err != nil {
		return "", fmt.Errorf(
			"java não encontrado e o download automático falhou: %w\n"+
				"Como resolver:\n"+
				"  1. Instale o JDK 21: https://adoptium.net/\n"+
				"  2. Verifique se java está no PATH: java --version\n"+
				"  3. Ou defina JAVA_HOME apontando para o JDK instalado",
			err,
		)
	}
	return javaPath, nil
}

// provisionJDK baixa o JDK 21 Temurin e extrai em ~/.hubsaude/jdk/.
// Retorna o caminho do executável java.
func provisionJDK() (string, error) {
	url, ext, err := temurinURL()
	if err != nil {
		return "", err
	}

	jdkDir := hubsaudePath("jdk")
	if err := os.MkdirAll(jdkDir, 0755); err != nil {
		return "", fmt.Errorf("criar diretório %s: %w", jdkDir, err)
	}

	// Arquivo temporário de download
	tmpFile := filepath.Join(jdkDir, "jdk-download"+ext)
	defer os.Remove(tmpFile)

	fmt.Fprintf(os.Stderr, "[info] Baixando de: %s\n", url)
	if err := downloadFile(tmpFile, url); err != nil {
		return "", fmt.Errorf("download do JDK: %w", err)
	}

	fmt.Fprintln(os.Stderr, "[info] Extraindo JDK...")
	if err := extractArchive(tmpFile, jdkDir, ext); err != nil {
		return "", fmt.Errorf("extrair JDK: %w", err)
	}

	// O arquivo extraído cria um subdiretório (ex: jdk-21+...). Precisamos encontrá-lo.
	javaBin, err := findJavaBinary(jdkDir)
	if err != nil {
		return "", err
	}

	fmt.Fprintf(os.Stderr, "[info] JDK 21 instalado em: %s\n", filepath.Dir(filepath.Dir(javaBin)))
	return javaBin, nil
}

// temurinURL retorna a URL de download do Temurin JDK 21 para o OS/arch atual.
func temurinURL() (url, ext string, err error) {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	var os_, arch string
	switch goos {
	case "linux":
		os_ = "linux"
	case "darwin":
		os_ = "mac"
	case "windows":
		os_ = "windows"
	default:
		return "", "", fmt.Errorf("sistema operacional não suportado para download automático: %s", goos)
	}

	switch goarch {
	case "amd64":
		arch = "x64"
	case "arm64":
		arch = "aarch64"
	case "386":
		arch = "x86-32"
	default:
		return "", "", fmt.Errorf("arquitetura não suportada para download automático: %s", goarch)
	}

	if goos == "windows" {
		ext = ".zip"
	} else {
		ext = ".tar.gz"
	}

	url = fmt.Sprintf(
		"https://api.adoptium.net/v3/binary/latest/%s/ga/%s/%s/jdk/hotspot/normal/eclipse",
		jdkVersion, os_, arch,
	)
	return url, ext, nil
}

// downloadFile baixa a URL para destPath com barra de progresso simples.
func downloadFile(destPath, url string) error {
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("resposta HTTP %d ao baixar %s", resp.StatusCode, url)
	}

	f, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

// extractArchive extrai tar.gz ou zip para destDir.
func extractArchive(archivePath, destDir, ext string) error {
	if strings.HasSuffix(ext, ".tar.gz") {
		return extractTarGz(archivePath, destDir)
	}
	return extractZip(archivePath, destDir)
}

func extractTarGz(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(destDir, hdr.Name) //nolint:gosec
		// Garantir que o destino está dentro de destDir (zip-slip protection)
		if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("entrada inválida no arquivo: %s", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil { //nolint:gosec
				out.Close()
				return err
			}
			out.Close()
		case tar.TypeSymlink:
			os.Symlink(hdr.Linkname, target) //nolint:errcheck
		}
	}
	return nil
}

func extractZip(archivePath, destDir string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		target := filepath.Join(destDir, f.Name) //nolint:gosec
		if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("entrada inválida no arquivo: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(target, 0755) //nolint:errcheck
			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
		if err != nil {
			rc.Close()
			return err
		}

		_, err = io.Copy(out, rc) //nolint:gosec
		out.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// findJavaBinary procura o executável java dentro de um diretório (um nível de subdiretório).
func findJavaBinary(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}

	binary := javaBinary()
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidate := filepath.Join(dir, entry.Name(), "bin", binary)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("executável java não encontrado após extração em %s", dir)
}

// logVerbose emite mensagem de diagnóstico quando --verbose está ativo.
func logVerbose(format string, args ...any) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[verbose] "+format+"\n", args...)
	}
}
