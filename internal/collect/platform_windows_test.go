//go:build windows

package collect

import "testing"

func TestNormalizeWindowsEventsUsesNormalizedFields(t *testing.T) {
	value := []any{map[string]any{"timestamp": "2026-08-07T12:00:00Z", "LevelDisplayName": "Error", "ProviderName": "Example", "Id": float64(42), "Message": "failed"}}
	events := normalizeWindowsEvents(value)
	if len(events) != 1 || events[0]["timestamp"] != "2026-08-07T12:00:00Z" || events[0]["severity"] != "error" || events[0]["source"] != "Example" {
		t.Fatalf("unexpected normalized event: %#v", events)
	}
}
