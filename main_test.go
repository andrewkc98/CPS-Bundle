package main

import (
	"testing"

	"cps-bundle/internal/model"
)

func TestNonOKSectionSummary(t *testing.T) {
	got := nonOKSectionSummary([]model.Result{
		{Section: "hardware", Status: "ok"},
		{Section: "network", Status: "partial"},
		{Section: "software", Status: "unavailable"},
	})
	if got != "network=partial, software=unavailable" {
		t.Fatalf("unexpected summary: %q", got)
	}
}

func TestStrictExitCode(t *testing.T) {
	complete := []model.Result{{Section: "hardware", Status: "ok"}, {Section: "software", Status: "skipped"}}
	degraded := []model.Result{{Section: "hardware", Status: "ok"}, {Section: "network", Status: "partial"}}
	if got := strictExitCode(false, degraded); got != 0 {
		t.Fatalf("default degraded exit code = %d, want 0", got)
	}
	if got := strictExitCode(true, complete); got != 0 {
		t.Fatalf("strict complete/skipped exit code = %d, want 0", got)
	}
	if got := strictExitCode(true, degraded); got != 3 {
		t.Fatalf("strict degraded exit code = %d, want 3", got)
	}
}
