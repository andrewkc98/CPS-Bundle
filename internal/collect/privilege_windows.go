//go:build windows

package collect

import (
	"errors"
	"os/exec"
	"strings"
)

func RequirePrivilege() error {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")
	out, err := cmd.Output()
	if err == nil && strings.EqualFold(strings.TrimSpace(string(out)), "true") {
		return nil
	}
	return errors.New("administrator privileges are required; relaunch the signed cps-bundle.exe with UAC approval")
}
