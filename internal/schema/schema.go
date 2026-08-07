package schema

import (
	_ "embed"
	"fmt"

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
	return nil
}
