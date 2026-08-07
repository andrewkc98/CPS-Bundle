package collect

import (
	"testing"
	"time"

	"cps-bundle/internal/model"
)

func TestSelected(t *testing.T) {
	opts := model.Options{Include: []string{"identity", "network"}}
	if !selected("identity", opts) || selected("software", opts) {
		t.Fatal("include filter did not select expected sections")
	}
	opts = model.Options{Exclude: []string{"network"}}
	if selected("network", opts) || !selected("identity", opts) {
		t.Fatal("exclude filter did not select expected sections")
	}
}

func TestNewBundleHasAllSections(t *testing.T) {
	b := model.NewBundle(model.Options{Since: 72 * time.Hour, CollectorVer: "test"}, time.Unix(0, 0))
	if b.Identity == nil || b.Hardware == nil || b.OperatingSystem == nil || b.Storage == nil || b.Network == nil || b.RecentErrors == nil || b.Software == nil || b.Findings == nil {
		t.Fatal("bundle sections must be initialized")
	}
}

func TestGroupErrorsPreservesRepetitionCount(t *testing.T) {
	events := []map[string]any{{"severity": "error", "source": "svc", "message": "failed", "timestamp": "2026-08-07T12:00:00Z"}, {"severity": "error", "source": "svc", "message": "failed", "timestamp": "2026-08-07T10:00:00Z"}}
	grouped := groupErrors(events)
	if len(grouped) != 1 || grouped[0]["occurrence_count"] != 2 || grouped[0]["first_occurrence"] != "2026-08-07T10:00:00Z" || grouped[0]["last_occurrence"] != "2026-08-07T12:00:00Z" {
		t.Fatalf("unexpected grouping: %#v", grouped)
	}
}
