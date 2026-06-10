//go:build windows

package cli

import "os/exec"

// detachProcess no Windows não precisa de configuração especial — o processo
// filho já roda de forma independente após cmd.Start().
func detachProcess(cmd *exec.Cmd) {}
