package schema

import (
	_ "embed"
	"fmt"
	"reflect"

	"cps-bundle/internal/model"
)

// Document is embedded so installed binaries can print and package the schema.
//
//go:embed bundle.schema.json
var Document string

// ValidateBundle performs the invariant checks that do not require a full
// third-party JSON Schema engine. The serialized document is also packaged
// with the archive so downstream systems can run complete validation.
func ValidateBundle(b model.Bundle) error {
	if b.Metadata.SchemaVersion == "" || b.Metadata.CollectorVersion == "" || b.Metadata.BundleID == "" || b.Metadata.CreatedAt == "" {
		return fmt.Errorf("metadata is incomplete")
	}
	if b.Identity == nil || b.Hardware == nil || b.OperatingSystem == nil || b.Storage == nil || b.Network == nil {
		return fmt.Errorf("one or more required object sections are nil")
	}
	if b.RecentErrors == nil || b.Software == nil || b.Findings == nil || b.Collection.Sections == nil || b.Collection.Warnings == nil {
		return fmt.Errorf("one or more required collection sections are nil")
	}
	for section, fields := range map[string]struct {
		value map[string]any
		keys  []string
	}{
		"storage": {value: b.Storage, keys: []string{"devices", "volumes"}},
		"network": {value: b.Network, keys: []string{"interfaces", "routes", "dns"}},
	} {
		for _, key := range fields.keys {
			if value, present := fields.value[key]; present && !isArray(value) {
				return fmt.Errorf("%s.%s must be an array", section, key)
			}
		}
	}
	if b.Collection.Status != "ok" && b.Collection.Status != "partial" {
		return fmt.Errorf("invalid collection status %q", b.Collection.Status)
	}
	for section, status := range b.Collection.Sections {
		if !validSectionStatus(status.Status) {
			return fmt.Errorf("invalid status %q for section %s", status.Status, section)
		}
	}
	for index, event := range b.RecentErrors {
		if severity, ok := event["severity"].(string); !ok || (severity != "critical" && severity != "error") {
			return fmt.Errorf("recent_errors[%d] has invalid severity", index)
		}
	}
	for index, item := range b.Software {
		if _, present := item["Publisher"]; present {
			return fmt.Errorf("software[%d] uses non-normalized key Publisher", index)
		}
		if _, present := item["InstallDate"]; present {
			return fmt.Errorf("software[%d] uses non-normalized key InstallDate", index)
		}
	}
	for index, finding := range b.Findings {
		if finding.Severity != "critical" && finding.Severity != "warning" && finding.Severity != "info" {
			return fmt.Errorf("findings[%d] has invalid severity %q", index, finding.Severity)
		}
	}
	return nil
}

func isArray(value any) bool {
	if value == nil {
		return false
	}
	return reflect.TypeOf(value).Kind() == reflect.Slice
}

func validSectionStatus(status string) bool {
	switch status {
	case "ok", "partial", "failed", "unavailable", "skipped":
		return true
	default:
		return false
	}
}
