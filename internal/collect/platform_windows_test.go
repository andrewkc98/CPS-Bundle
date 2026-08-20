//go:build windows

package collect

import (
	"strings"
	"testing"
)

func TestNormalizeWindowsEventsUsesNormalizedFields(t *testing.T) {
	value := []any{map[string]any{"timestamp": "2026-08-07T12:00:00Z", "Level": float64(2), "LevelDisplayName": "Erreur", "ProviderName": "Example", "Id": float64(42), "Message": "failed"}}
	events := normalizeWindowsEvents(value)
	if len(events) != 1 || events[0]["timestamp"] != "2026-08-07T12:00:00Z" || events[0]["severity"] != "error" || events[0]["source"] != "Example" {
		t.Fatalf("unexpected normalized event: %#v", events)
	}
}

func TestNormalizeWindowsEventsUsesNumericCriticalLevel(t *testing.T) {
	events := normalizeWindowsEvents([]any{map[string]any{"Level": float64(1), "LevelDisplayName": "Kritisch"}})
	if len(events) != 1 || events[0]["severity"] != "critical" {
		t.Fatalf("unexpected normalized event: %#v", events)
	}
}

func TestParseWindowsEventsOutputTreatsEmptyAsEmptyList(t *testing.T) {
	value, err := parseWindowsEventsOutput(" \r\n")
	if err != nil {
		t.Fatalf("parseWindowsEventsOutput returned error: %v", err)
	}
	items, ok := value.([]any)
	if !ok || len(items) != 0 {
		t.Fatalf("unexpected empty event value: %#v", value)
	}
}

func TestNormalizeWindowsIdentityRejectsNonObjectPayloads(t *testing.T) {
	for _, value := range []any{nil, "identity", []any{map[string]any{}}} {
		if _, err := normalizeWindowsIdentity(value, "amd64"); err == nil {
			t.Fatalf("expected identity error for %#v", value)
		}
	}
	identity, err := normalizeWindowsIdentity(map[string]any{"serial": " To Be Filled By O.E.M. "}, "amd64")
	if err != nil || identity["serial"] != nil || identity["architecture"] != "amd64" {
		t.Fatalf("unexpected normalized identity: %#v, %v", identity, err)
	}
}

func TestNormalizeWindowsStorageAndNetworkAlwaysUseArrays(t *testing.T) {
	storage := normalizeWindowsStorage(map[string]any{
		"devices": map[string]any{"FriendlyName": "disk0", "SerialNumber": "serial", "MediaType": "SSD", "Size": float64(1000), "HealthStatus": "Healthy"},
		"volumes": map[string]any{"drive_letter": "C", "filesystem": "NTFS", "size_bytes": float64(1000), "free_bytes": float64(50), "health": "Healthy"},
		"health":  "healthy",
	})
	for _, key := range []string{"devices", "volumes"} {
		if values, ok := storage[key].([]any); !ok || len(values) != 1 {
			t.Fatalf("storage %s was not a one-item array: %#v", key, storage[key])
		}
	}
	volume := storage["volumes"].([]any)[0].(map[string]any)
	if volume["filesystem"] != "C" || volume["mount_point"] != "C:\\" || volume["filesystem_type"] != "ntfs" || volume["used_percent"] != float64(95) || volume["health"] != "healthy" {
		t.Fatalf("unexpected normalized volume: %#v", volume)
	}
	disk := storage["devices"].([]any)[0].(map[string]any)
	if disk["name"] != "disk0" || disk["serial"] != "serial" || disk["media_type"] != "ssd" || disk["health"] != "healthy" || disk["size_bytes"] != float64(1000) {
		t.Fatalf("unexpected normalized disk: %#v", disk)
	}
	network := normalizeWindowsNetwork(map[string]any{
		"config": map[string]any{"InterfaceAlias": "Ethernet", "NetAdapter": map[string]any{"Status": "Up", "MacAddress": "00-11-22-33-44-55"}, "IPv4Address": map[string]any{"IPAddress": "192.0.2.10", "PrefixLength": float64(24)}, "IPv6Address": map[string]any{"IPAddress": "2001:db8::10", "PrefixLength": float64(64)}},
		"routes": map[string]any{"DestinationPrefix": "0.0.0.0/0", "NextHop": "192.0.2.1", "InterfaceAlias": "Ethernet", "RouteMetric": float64(10), "Protocol": "NetMgmt"},
		"dns":    []any{map[string]any{"ServerAddresses": []any{"192.0.2.53", "2001:db8::53"}}, map[string]any{"ServerAddresses": []any{"192.0.2.53"}}},
	})
	for _, key := range []string{"interfaces", "routes", "dns"} {
		if key == "dns" {
			continue
		}
		if values, ok := network[key].([]any); !ok || len(values) != 1 {
			t.Fatalf("network %s was not a one-item array: %#v", key, network[key])
		}
	}
	iface := network["interfaces"].([]any)[0].(map[string]any)
	if iface["name"] != "Ethernet" || iface["state"] != "active" || iface["mac_address"] != "00-11-22-33-44-55" || len(iface["addresses"].([]any)) != 2 {
		t.Fatalf("unexpected normalized interface: %#v", iface)
	}
	dns := network["dns"].([]string)
	if len(dns) != 2 || dns[0] != "192.0.2.53" || dns[1] != "2001:db8::53" {
		t.Fatalf("unexpected flattened DNS: %#v", dns)
	}
}

func TestNormalizeWindowsSoftwareUsesLowercaseContract(t *testing.T) {
	software := normalizeWindowsSoftware(map[string]any{"name": "App", "version": "1.0", "Publisher": "Vendor", "InstallDate": "20260820"})
	if len(software) != 1 || software[0]["publisher"] != "Vendor" || software[0]["install_date"] != "20260820" {
		t.Fatalf("unexpected normalized software: %#v", software)
	}
	if _, ok := software[0]["Publisher"]; ok {
		t.Fatalf("software has non-normalized keys: %#v", software[0])
	}
}

func TestWindowsEvidenceIsBoundedAndMarkedTruncated(t *testing.T) {
	raw := strings.Repeat("x", 32)
	evidence, truncated := windowsEvidence("evidence/test.json", raw, 16)
	if !truncated || len(evidence) != 1 || !strings.HasSuffix(string(evidence[0].Content), "\n[truncated]\n") {
		t.Fatalf("unexpected bounded evidence: truncated=%v evidence=%#v", truncated, evidence)
	}
}
