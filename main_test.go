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
