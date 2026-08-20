package bundle

import (
	"archive/zip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"cps-bundle/internal/model"
)

func TestWriteCreatesOfflineBundleAndManifest(t *testing.T) {
	dir := t.TempDir()
	opts := model.Options{Output: dir, Since: time.Hour, CollectorVer: "test", Yes: true}
	doc := model.NewBundle(opts, time.Unix(0, 0))
	doc.Identity["hostname"] = "test-host"
	path, err := Write(opts, doc, []model.Result{{Section: "identity", Status: "ok", Source: "fixture", Evidence: []model.Evidence{{Name: "evidence/test.txt", Content: []byte("fixture")}}}})
	if err != nil {
		t.Fatal(err)
	}
	archive, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	wanted := map[string]bool{"00-summary.html": false, "bundle.json": false, "manifest.json": false, "schema/bundle.schema.json": false, "evidence/test.txt": false}
	for _, file := range archive.File {
		if _, ok := wanted[file.Name]; ok {
			wanted[file.Name] = true
		}
	}
	for name, found := range wanted {
		if !found {
			t.Errorf("missing %s", name)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "test-host")); err == nil {
		t.Fatal("unexpected directory output")
	}
}

func TestWriteRedactedOmitsEvidenceAndRecordsWarning(t *testing.T) {
	dir := t.TempDir()
	opts := model.Options{Output: dir, Since: time.Hour, CollectorVer: "test", Yes: true, Redact: true}
	doc := model.NewBundle(opts, time.Unix(0, 0))
	doc.Identity["hostname"] = "test-host"
	path, err := Write(opts, doc, []model.Result{{Section: "network", Status: "failed", Source: "fixture", Error: "sensitive fixture error", Evidence: []model.Evidence{{Name: "evidence/raw.txt", Content: []byte("sensitive fixture evidence")}}}})
	if err != nil {
		t.Fatal(err)
	}
	archive, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	if _, found := archiveEntry(archive, "evidence/raw.txt"); found {
		t.Fatal("redacted bundle included raw evidence")
	}
	bundleJSON, found := archiveEntry(archive, "bundle.json")
	if !found {
		t.Fatal("bundle.json missing")
	}
	var packaged model.Bundle
	if err := json.Unmarshal(bundleJSON, &packaged); err != nil {
		t.Fatal(err)
	}
	if packaged.Collection.EvidenceTruncated {
		t.Fatal("omitted evidence must not be reported as truncated")
	}
	if !strings.Contains(strings.Join(packaged.Collection.Warnings, "\n"), "Raw evidence files were omitted") {
		t.Fatal("packaged bundle is missing the evidence omission warning")
	}
	summaryHTML, found := archiveEntry(archive, "00-summary.html")
	if !found || !strings.Contains(string(summaryHTML), "Raw evidence files were omitted") {
		t.Fatal("summary is missing the evidence omission warning")
	}
	collectionLog, found := archiveEntry(archive, "collection.log")
	if !found || strings.Contains(string(collectionLog), "sensitive fixture error") || !strings.Contains(string(collectionLog), "[REDACTED]") {
		t.Fatal("redacted collection log did not replace the result error")
	}
}

func TestWriteFinalArchiveModeIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file mode assertion")
	}
	dir := t.TempDir()
	opts := model.Options{Output: filepath.Join(dir, "result.zip"), Since: time.Hour, CollectorVer: "test", Yes: true}
	doc := model.NewBundle(opts, time.Unix(0, 0))
	path, err := Write(opts, doc, nil)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("archive mode = %04o, want 0600", got)
	}
}

func TestParseSudoIdentity(t *testing.T) {
	tests := []struct {
		name    string
		values  map[string]string
		wantNil bool
		wantUID int
		wantGID int
		wantErr string
	}{
		{name: "absent", values: map[string]string{}, wantNil: true},
		{name: "valid", values: map[string]string{"SUDO_UID": "501", "SUDO_GID": "20"}, wantUID: 501, wantGID: 20},
		{name: "partial", values: map[string]string{"SUDO_UID": "501"}, wantErr: "both numeric"},
		{name: "invalid uid", values: map[string]string{"SUDO_UID": "abc", "SUDO_GID": "20"}, wantErr: "invalid SUDO_UID"},
		{name: "negative gid", values: map[string]string{"SUDO_UID": "501", "SUDO_GID": "-1"}, wantErr: "invalid SUDO_GID"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity, err := parseSudoIdentity(func(key string) string { return test.values[key] })
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if test.wantNil {
				if identity != nil {
					t.Fatalf("identity = %#v, want nil", identity)
				}
				return
			}
			if identity == nil || identity.uid != test.wantUID || identity.gid != test.wantGID {
				t.Fatalf("identity = %#v, want uid=%d gid=%d", identity, test.wantUID, test.wantGID)
			}
		})
	}
}

func TestDestinationPathDoesNotCreateOutputDirectories(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "nested", "output")
	doc := model.NewBundle(model.Options{}, time.Unix(0, 0))
	destination, outputDirectory, err := destinationPath(output, doc)
	if err != nil {
		t.Fatal(err)
	}
	if outputDirectory != output || filepath.Dir(destination) != output {
		t.Fatalf("destination = %q, output directory = %q", destination, outputDirectory)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("destinationPath created output directory or returned unexpected error: %v", err)
	}
}

func TestWriteRejectsPreexistingPartialWithoutTouchingTarget(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "result.zip")
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("keep me"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, destination+".partial"); err != nil {
		t.Skipf("symlink setup unavailable: %v", err)
	}
	opts := model.Options{Output: destination, Since: time.Hour, CollectorVer: "test", Yes: true}
	doc := model.NewBundle(opts, time.Unix(0, 0))
	if _, err := Write(opts, doc, nil); err == nil {
		t.Fatal("expected preexisting partial to be rejected")
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "keep me" {
		t.Fatalf("preexisting partial target was modified: %q", content)
	}
	if _, err := os.Lstat(destination + ".partial"); err != nil {
		t.Fatalf("preexisting partial was unexpectedly removed: %v", err)
	}
}

func TestWriteEmptyEvidenceDoesNotSetTruncation(t *testing.T) {
	dir := t.TempDir()
	opts := model.Options{Output: dir, Since: time.Hour, CollectorVer: "test", Yes: true}
	doc := model.NewBundle(opts, time.Unix(0, 0))
	doc.Identity["hostname"] = "test-host"
	path, err := Write(opts, doc, []model.Result{{Section: "identity", Status: "ok", Source: "fixture", Evidence: []model.Evidence{{Name: "evidence/empty.txt"}}}})
	if err != nil {
		t.Fatal(err)
	}
	archive, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	bundleJSON, found := archiveEntry(archive, "bundle.json")
	if !found {
		t.Fatal("bundle.json missing")
	}
	var packaged model.Bundle
	if err := json.Unmarshal(bundleJSON, &packaged); err != nil {
		t.Fatal(err)
	}
	if packaged.Collection.EvidenceTruncated {
		t.Fatal("empty evidence must not be reported as truncated")
	}
	if _, found := archiveEntry(archive, "evidence/empty.txt"); found {
		t.Fatal("empty evidence should not be packaged")
	}
}

func archiveEntry(archive *zip.ReadCloser, name string) ([]byte, bool) {
	for _, file := range archive.File {
		if file.Name != name {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			return nil, false
		}
		defer reader.Close()
		data, err := io.ReadAll(reader)
		return data, err == nil
	}
	return nil, false
}
