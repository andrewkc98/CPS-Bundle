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
	"strconv"
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

type sudoIdentity struct {
	uid int
	gid int
}

func Write(opts model.Options, doc model.Bundle, results []model.Result) (string, error) {
	if err := schema.ValidateBundle(doc); err != nil {
		return "", err
	}
	identity, err := parseSudoIdentity(os.Getenv)
	if err != nil {
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
	if opts.Redact {
		doc.Collection.Warnings = append(doc.Collection.Warnings, "Raw evidence files were omitted because redaction was requested.")
	}
	for _, result := range results {
		errorText := result.Error
		if opts.Redact && errorText != "" {
			errorText = "[REDACTED]"
		}
		logLines = append(logLines, fmt.Sprintf("%s\t%s\t%dms\t%s\t%s", result.Section, result.Status, result.DurationMS, result.Source, errorText))
		if opts.Redact {
			continue
		}
		for _, evidence := range result.Evidence {
			if len(evidence.Content) == 0 {
				continue
			}
			if usedEvidence >= evidenceLimit {
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
	summaryHTML := summary.RenderHTML(doc)
	if opts.Redact {
		summaryHTML = appendSummaryWarning(summaryHTML, "Raw evidence files were omitted because redaction was requested.")
	}
	files["00-summary.html"] = summaryHTML
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

	destination, outputDirectory, err := destinationPath(opts.Output, doc)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(destination); err == nil {
		return "", fmt.Errorf("output already exists: %s", destination)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	createdDirs, err := ensureOutputDirectory(outputDirectory)
	if err != nil {
		return "", err
	}
	partial := destination + ".partial"
	file, created, err := zipDir(partial, temp, files)
	if err != nil {
		if created {
			os.Remove(partial)
		}
		return "", err
	}
	if err := finalizeArchive(file, partial, destination, identity, createdDirs); err != nil {
		return "", err
	}
	return destination, nil
}

func destinationPath(output string, doc model.Bundle) (string, string, error) {
	if output == "" {
		output = "."
	}
	info, err := os.Stat(output)
	if err == nil && info.IsDir() {
		return filepath.Join(output, archiveName(doc)), filepath.Clean(output), nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", "", err
	}
	if strings.HasSuffix(strings.ToLower(output), ".zip") {
		destination := filepath.Clean(output)
		return destination, filepath.Dir(destination), nil
	}
	if err == nil {
		return "", "", fmt.Errorf("output path is not a directory: %s", output)
	}
	directory := filepath.Clean(output)
	return filepath.Join(directory, archiveName(doc)), directory, nil
}

func archiveName(doc model.Bundle) string {
	return fmt.Sprintf("cps-bundle_%s_%s.zip", safe(doc.Identity["hostname"]), time.Now().UTC().Format("20060102T150405Z"))
}

func ensureOutputDirectory(directory string) ([]string, error) {
	directory = filepath.Clean(directory)
	missing := []string{}
	for current := directory; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if !info.IsDir() {
				return nil, fmt.Errorf("output path component is not a directory: %s", current)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil, fmt.Errorf("no existing parent directory for output: %s", directory)
		}
		missing = append(missing, current)
	}
	created := make([]string, 0, len(missing))
	for index := len(missing) - 1; index >= 0; index-- {
		path := missing[index]
		if err := os.Mkdir(path, 0700); err == nil {
			created = append(created, path)
			continue
		} else if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("output path component is not a directory: %s", path)
		}
	}
	return created, nil
}

func parseSudoIdentity(lookup func(string) string) (*sudoIdentity, error) {
	uidText := lookup("SUDO_UID")
	gidText := lookup("SUDO_GID")
	if uidText == "" && gidText == "" {
		return nil, nil
	}
	if uidText == "" || gidText == "" {
		return nil, errors.New("sudo ownership correction requires both numeric SUDO_UID and SUDO_GID")
	}
	uid, err := parseID(uidText)
	if err != nil {
		return nil, fmt.Errorf("invalid SUDO_UID for ownership correction: %w", err)
	}
	gid, err := parseID(gidText)
	if err != nil {
		return nil, fmt.Errorf("invalid SUDO_GID for ownership correction: %w", err)
	}
	return &sudoIdentity{uid: uid, gid: gid}, nil
}

func parseID(value string) (int, error) {
	parsed, err := strconv.ParseUint(value, 10, 31)
	if err != nil {
		return 0, fmt.Errorf("must be a non-negative decimal integer")
	}
	return int(parsed), nil
}

func zipDir(destination, root string, files map[string][]byte) (*os.File, bool, error) {
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, false, err
	}
	archive := zip.NewWriter(file)
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		entry, err := archive.Create(filepath.ToSlash(path))
		if err != nil {
			archive.Close()
			file.Close()
			return nil, true, err
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			archive.Close()
			file.Close()
			return nil, true, err
		}
		if _, err := io.Copy(entry, bytes.NewReader(data)); err != nil {
			archive.Close()
			file.Close()
			return nil, true, err
		}
	}
	if err := archive.Close(); err != nil {
		file.Close()
		return nil, true, err
	}
	return file, true, nil
}

func appendSummaryWarning(summaryHTML []byte, warning string) []byte {
	const closingFooter = "</footer>"
	message := []byte("<br><strong>Warning:</strong> " + warning)
	if index := bytes.Index(summaryHTML, []byte(closingFooter)); index >= 0 {
		return append(append(append([]byte(nil), summaryHTML[:index]...), message...), summaryHTML[index:]...)
	}
	return append(summaryHTML, message...)
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
