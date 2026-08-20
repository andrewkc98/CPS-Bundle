package schema

import (
	"os"
	"testing"
	"time"

	"cps-bundle/internal/model"
)

func TestValidateBundleRejectsNormalizedShapeDrift(t *testing.T) {
	bundle := model.NewBundle(model.Options{CollectorVer: "test"}, time.Unix(0, 0))
	bundle.Storage["volumes"] = map[string]any{"mount_point": "/"}
	if err := ValidateBundle(bundle); err == nil {
		t.Fatal("single-object volume shape was accepted")
	}
	bundle.Storage["volumes"] = []any{map[string]any{"mount_point": "/"}}
	bundle.Software = []map[string]any{{"name": "app", "Publisher": "vendor"}}
	if err := ValidateBundle(bundle); err == nil {
		t.Fatal("legacy software key was accepted")
	}
}

func TestTrackedSchemaMatchesEmbeddedSchema(t *testing.T) {
	tracked, err := os.ReadFile("../../schema/bundle.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(tracked) != Document {
		t.Fatal("tracked and embedded schema copies differ")
	}
}
