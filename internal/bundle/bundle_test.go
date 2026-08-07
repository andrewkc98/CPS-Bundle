package bundle

import (
	"archive/zip"
	"os"
	"path/filepath"
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
