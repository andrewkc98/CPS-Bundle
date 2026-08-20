//go:build !windows

package bundle

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"cps-bundle/internal/model"
)

func TestWriteSudoOwnershipForNewOutputDirectories(t *testing.T) {
	t.Setenv("SUDO_UID", strconv.Itoa(os.Getuid()))
	t.Setenv("SUDO_GID", strconv.Itoa(os.Getgid()))
	output := filepath.Join(t.TempDir(), "new", "nested")
	opts := model.Options{Output: output, Since: time.Hour, CollectorVer: "test", Yes: true}
	doc := model.NewBundle(opts, time.Unix(0, 0))
	path, err := Write(opts, doc, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{path, filepath.Dir(output), output} {
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("missing Unix stat data for %s", target)
		}
		if int(stat.Uid) != os.Getuid() || int(stat.Gid) != os.Getgid() {
			t.Fatalf("ownership for %s = %d:%d, want %d:%d", target, stat.Uid, stat.Gid, os.Getuid(), os.Getgid())
		}
	}
}
