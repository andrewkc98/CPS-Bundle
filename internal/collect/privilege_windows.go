//go:build windows

package collect

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

func RequirePrivilege() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")
	out, err := cmd.Output()
	if err == nil && strings.EqualFold(strings.TrimSpace(string(out)), "true") {
		return nil
	}
	return errors.New("administrator privileges are required; relaunch the signed cps-bundle.exe with UAC approval")
}
