package model

import (
	"reflect"
	"testing"
	"time"
)

func TestRedactCoversStructuredAndFreeTextIdentifiers(t *testing.T) {
	bundle := NewBundle(Options{CollectorVer: "test"}, time.Unix(0, 0))
	bundle.Identity["hostname"] = "support-host"
	bundle.OperatingSystem["last_updates"] = []string{"Requested-By: local-user"}
	bundle.Network["dns"] = []string{"192.0.2.53", "fe80::1%eth0", "resolver-label"}
	bundle.Network["interfaces"] = []map[string]any{{
		"name":      "eth0",
		"addresses": []map[string]any{{"address": "192.0.2.10"}},
	}}
	bundle.Network["routes"] = []map[string]any{{"gateway": "192.0.2.1", "destination": "192.0.2.0/24", "raw": "native route output"}}
	bundle.RecentErrors = []map[string]any{{"source": "service", "message": "user data", "native_code": "1"}}
	bundle.Collection.Sections["network"] = SectionStatus{Status: "failed", Error: "/private/user/path"}

	Redact(&bundle)

	if bundle.Identity["hostname"] != "[REDACTED]" || !bundle.Metadata.Redacted {
		t.Fatalf("identity or metadata was not redacted: %#v", bundle.Identity)
	}
	if got := bundle.OperatingSystem["last_updates"]; !reflect.DeepEqual(got, []string{"[REDACTED]"}) {
		t.Fatalf("update history was not redacted: %#v", got)
	}
	dns := bundle.Network["dns"].([]string)
	if dns[0] != "[REDACTED]" || dns[1] != "[REDACTED]" || dns[2] != "resolver-label" {
		t.Fatalf("DNS identifiers were not redacted: %#v", dns)
	}
	interfaces := bundle.Network["interfaces"].([]map[string]any)
	addresses := interfaces[0]["addresses"].([]map[string]any)
	if addresses[0]["address"] != "[REDACTED]" {
		t.Fatalf("typed interface slice was not redacted: %#v", interfaces)
	}
	routes := bundle.Network["routes"].([]map[string]any)
	if routes[0]["gateway"] != "[REDACTED]" || routes[0]["destination"] != "[REDACTED]" || routes[0]["raw"] != "[REDACTED]" {
		t.Fatalf("route identifiers were not redacted: %#v", routes)
	}
	if bundle.RecentErrors[0]["message"] != "[REDACTED]" {
		t.Fatalf("event message was not redacted: %#v", bundle.RecentErrors)
	}
	if bundle.Collection.Sections["network"].Error != "[REDACTED]" {
		t.Fatalf("collector error was not redacted: %#v", bundle.Collection.Sections["network"])
	}
}
