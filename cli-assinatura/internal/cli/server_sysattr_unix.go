//go:build !windows

package cli

import (
	"os/exec"
	"syscall"
)

// detachProcess configura o processo para rodar em uma nova sessão de processo
// (setsid), desanexando-o do terminal do CLI. Assim, Ctrl+C no terminal não
// encerra o servidor em background.
func detachProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
