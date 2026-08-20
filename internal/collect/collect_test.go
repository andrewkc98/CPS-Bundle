package collect

import (
	"context"
	"strings"
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

func TestValidateSelectionsRejectsUnknownCategory(t *testing.T) {
	collectors := []Collector{{Section: "identity"}, {Section: "network"}}
	err := validateSelections(collectors, model.Options{Include: []string{"identity", "typo"}})
	if err == nil || !strings.Contains(err.Error(), "--include") || !strings.Contains(err.Error(), "typo") || !strings.Contains(err.Error(), "identity, network") {
		t.Fatalf("unexpected validation error: %v", err)
	}
	if err := validateSelections(collectors, model.Options{Exclude: []string{"network"}}); err != nil {
		t.Fatalf("known category rejected: %v", err)
	}
}

func TestSkippedSectionsDoNotMakeCollectionIncomplete(t *testing.T) {
	sections := map[string]model.SectionStatus{
		"identity": {Status: "ok"},
		"network":  {Status: "skipped"},
	}
	if hasIncompleteSections(sections) {
		t.Fatal("intentional skipped section should not make collection partial")
	}
	sections["software"] = model.SectionStatus{Status: "partial"}
	if !hasIncompleteSections(sections) {
		t.Fatal("partial section should make collection partial")
	}
}

func TestRunCollectorConvertsPanicToFailedResult(t *testing.T) {
	result := runCollector(context.Background(), Collector{
		Section: "network", Source: "test", Timeout: time.Second,
		Run: func(context.Context) (any, []model.Evidence, []string, []string, bool, error) {
			panic("unexpected collector failure")
		},
	})
	if result.Status != "failed" || !strings.Contains(result.Error, "collector panic: unexpected collector failure") {
		t.Fatalf("panic was not converted to a failed result: %#v", result)
	}
}

func TestFindingsPrioritizeCriticalBeforeTruncation(t *testing.T) {
	b := model.NewBundle(model.Options{Since: time.Hour}, time.Unix(0, 0))
	for i := 0; i < 10; i++ {
		b.Collection.Sections["failed-"+string(rune('a'+i))] = model.SectionStatus{Status: "failed", Error: "test"}
	}
	b.Storage["volumes"] = []any{map[string]any{"used_percent": 99.0}}
	findings := findings(b)
	if len(findings) != 10 || findings[0].Severity != "critical" || findings[0].Title != "Storage critically full" {
		t.Fatalf("critical finding was not retained first: %#v", findings)
	}
}

func TestGroupErrorsPreservesRepetitionCount(t *testing.T) {
	events := []map[string]any{{"severity": "error", "source": "svc", "message": "failed", "timestamp": "2026-08-07T12:00:00Z"}, {"severity": "error", "source": "svc", "message": "failed", "timestamp": "2026-08-07T10:00:00Z"}}
	grouped := groupErrors(events)
	if len(grouped) != 1 || grouped[0]["occurrence_count"] != 2 || grouped[0]["first_occurrence"] != "2026-08-07T10:00:00Z" || grouped[0]["last_occurrence"] != "2026-08-07T12:00:00Z" {
		t.Fatalf("unexpected grouping: %#v", grouped)
	}
}
