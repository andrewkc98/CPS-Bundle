//go:build !windows

package bundle

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

func TestFinalizeArchiveDoesNotReplaceDestinationCreatedAfterPartial(t *testing.T) {
	dir := t.TempDir()
	partial := filepath.Join(dir, "result.zip.partial")
	archive := filepath.Join(dir, "result.zip")
	file, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("our partial archive"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, []byte("another writer won"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := finalizeArchive(file, partial, archive, nil, nil); err == nil {
		t.Fatal("expected destination collision to fail")
	} else if !strings.Contains(err.Error(), "was not replaced") {
		t.Fatalf("collision error = %v", err)
	}
	content, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "another writer won" {
		t.Fatalf("destination content changed: %q", content)
	}
	if _, err := os.Lstat(partial); !os.IsNotExist(err) {
		t.Fatalf("our partial was not cleaned up: %v", err)
	}
}
