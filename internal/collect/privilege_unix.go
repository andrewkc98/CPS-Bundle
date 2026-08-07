//go:build !windows

package collect

import (
	"errors"
	"fmt"
	"os"
	"runtime"
)

func RequirePrivilege() error {
	if os.Geteuid() == 0 {
		return nil
	}
	return errors.New(fmt.Sprintf("administrator privileges are required; rerun with sudo cps-bundle (current OS: %s)", runtime.GOOS))
}
