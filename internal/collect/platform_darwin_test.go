//go:build darwin

package collect

import (
	"testing"
	"time"
)

func TestParseMacLogNDJSON(t *testing.T) {
	text := "{\"timestamp\":\"2026-08-07 12:00:00.123456+0000\",\"messageType\":\"Fault\",\"subsystem\":\"example\",\"category\":\"test\",\"eventMessage\":\"failed\"}\n"
	events := parseMacLog(text, 10)
	if len(events) != 1 || events[0]["severity"] != "critical" || events[0]["source"] != "example" || events[0]["timestamp"] != "2026-08-07T12:00:00.123456Z" {
		t.Fatalf("unexpected normalized event: %#v", events)
	}
}

func TestMacLogLookbackRoundsUp(t *testing.T) {
	if got := macLogLookback(90 * time.Minute); got != "2h" {
		t.Fatalf("unexpected lookback: %s", got)
	}
}

func TestParseMacStorageAndNetwork(t *testing.T) {
	volumes := parseMacVolumes("/dev/disk3s5 1000 750 250 75% /System/Volumes/Data\n")
	if len(volumes) != 1 {
		t.Fatalf("unexpected volumes: %#v", volumes)
	}
	interfaces := parseMacInterfaces("en0: flags=8863<UP> mtu 1500\n\tether aa:bb:cc:dd:ee:ff\n\tinet 192.0.2.1 netmask 0xffffff00\n\tstatus: active\n")
	if len(interfaces) != 1 || interfaces[0]["name"] != "en0" || interfaces[0]["state"] != "active" {
		t.Fatalf("unexpected interfaces: %#v", interfaces)
	}
	dns := parseMacDNS("nameserver[0] : 192.0.2.53\nnameserver[1] : 192.0.2.53\n")
	if len(dns) != 1 || dns[0] != "192.0.2.53" {
		t.Fatalf("unexpected DNS: %#v", dns)
	}
}
