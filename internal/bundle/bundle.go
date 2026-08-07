package bundle

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cps-bundle/internal/model"
	"cps-bundle/internal/schema"
	"cps-bundle/internal/summary"
)

type manifestFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type manifest struct {
	SchemaVersion    string         `json:"schema_version"`
	CollectorVersion string         `json:"collector_version"`
	CreatedAt        string         `json:"created_at"`
	Files            []manifestFile `json:"files"`
}

func Write(opts model.Options, doc model.Bundle, results []model.Result) (string, error) {
	if err := schema.ValidateBundle(doc); err != nil {
		return "", err
	}
	temp, err := os.MkdirTemp("", "cps-bundle-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(temp)
	files := map[string][]byte{}
	logLines := []string{}
	const evidenceLimit = 50 << 20
	usedEvidence := 0
	for _, result := range results {
		logLines = append(logLines, fmt.Sprintf("%s\t%s\t%dms\t%s\t%s", result.Section, result.Status, result.DurationMS, result.Source, result.Error))
		for _, evidence := range result.Evidence {
			if len(evidence.Content) == 0 || usedEvidence >= evidenceLimit {
				doc.Collection.EvidenceTruncated = true
				continue
			}
			content := evidence.Content
			remaining := evidenceLimit - usedEvidence
			if len(content) > remaining {
				marker := []byte("\n[truncated by bundle cap]\n")
				if remaining <= len(marker) {
					content = marker[:remaining]
				} else {
					content = append(append([]byte(nil), content[:remaining-len(marker)]...), marker...)
				}
				doc.Collection.EvidenceTruncated = true
			}
			files[evidence.Name] = content
			usedEvidence += len(content)
		}
	}
	jsonData, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	files["bundle.json"] = append(jsonData, '\n')
	files["00-summary.html"] = summary.RenderHTML(doc)
	files["schema/bundle.schema.json"] = []byte(schema.Document)
	sort.Strings(logLines)
	files["collection.log"] = []byte(strings.Join(logLines, "\n") + "\n")
	for path, data := range files {
		target := filepath.Join(temp, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return "", err
		}
		if err := os.WriteFile(target, data, 0600); err != nil {
			return "", err
		}
	}
	m := manifest{SchemaVersion: doc.Metadata.SchemaVersion, CollectorVersion: doc.Metadata.CollectorVersion, CreatedAt: doc.Metadata.CreatedAt}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		hash := sha256.Sum256(files[path])
		m.Files = append(m.Files, manifestFile{Path: path, Bytes: int64(len(files[path])), SHA256: hex.EncodeToString(hash[:])})
	}
	manifestData, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	manifestData = append(manifestData, '\n')
	files["manifest.json"] = manifestData
	manifestPath := filepath.Join(temp, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestData, 0600); err != nil {
		return "", err
	}

	destination, err := destinationPath(opts.Output, doc)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(destination); err == nil {
		return "", fmt.Errorf("output already exists: %s", destination)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		return "", err
	}
	partial := destination + ".partial"
	if _, err := os.Stat(partial); err == nil {
		return "", fmt.Errorf("temporary output already exists: %s", partial)
	}
	if err := zipDir(partial, temp, files); err != nil {
		os.Remove(partial)
		return "", err
	}
	if err := os.Rename(partial, destination); err != nil {
		os.Remove(partial)
		return "", err
	}
	return destination, nil
}

func destinationPath(output string, doc model.Bundle) (string, error) {
	if output == "" {
		output = "."
	}
	info, err := os.Stat(output)
	if err == nil && info.IsDir() {
		return filepath.Join(output, fmt.Sprintf("cps-bundle_%s_%s.zip", safe(doc.Identity["hostname"]), time.Now().UTC().Format("20060102T150405Z"))), nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if strings.HasSuffix(strings.ToLower(output), ".zip") {
		return filepath.Clean(output), nil
	}
	if err := os.MkdirAll(output, 0700); err != nil {
		return "", err
	}
	return filepath.Join(output, fmt.Sprintf("cps-bundle_%s_%s.zip", safe(doc.Identity["hostname"]), time.Now().UTC().Format("20060102T150405Z"))), nil
}

func zipDir(destination, root string, files map[string][]byte) error {
	file, err := os.Create(destination)
	if err != nil {
		return err
	}
	defer file.Close()
	archive := zip.NewWriter(file)
	defer archive.Close()
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		entry, err := archive.Create(filepath.ToSlash(path))
		if err != nil {
			return err
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return err
		}
		if _, err := io.Copy(entry, bytes.NewReader(data)); err != nil {
			return err
		}
	}
	return nil
}
func safe(value any) string {
	text := fmt.Sprint(value)
	if text == "<nil>" || text == "" {
		return "host"
	}
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, text)
}
