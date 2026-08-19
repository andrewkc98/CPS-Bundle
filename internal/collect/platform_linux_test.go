//go:build linux

package collect

import (
	"encoding/json"
	"testing"
)

func TestLinuxNormalization(t *testing.T) {
	if model := linuxCPUInfoModel("processor\t: 0\nBogoMIPS\t: 48.00\n"); model != "" {
		t.Fatalf("processor index used as CPU model: %q", model)
	}
	if model := linuxCPUInfoModel("model name\t: Example CPU\n"); model != "Example CPU" {
		t.Fatalf("unexpected proc CPU model: %q", model)
	}

	var lscpu any
	mustJSON(t, `{"lscpu":[{"field":"Vendor ID:","data":"Apple"},{"field":"Model name:","data":"-"}]}`, &lscpu)
	model, vendor := linuxCPUDescription(lscpu, "")
	if model != "" || vendor != "Apple" {
		t.Fatalf("unexpected CPU description: %q %q", model, vendor)
	}

	var blocks any
	mustJSON(t, `{"blockdevices":[{"name":"loop0","type":"loop"},{"name":"vda","type":"disk","size":1000,"rota":true,"model":null}]}`, &blocks)
	if devices := parseLinuxBlockDevices(blocks); len(devices) != 1 {
		t.Fatalf("unexpected devices: %#v", devices)
	}

	var mounts any
	mustJSON(t, `{"filesystems":[{"source":"/dev/vda2","target":"/","fstype":"ext4","size":1000,"avail":250,"use%":"75%","children":[{"source":"/dev/loop0","target":"/snap/x","fstype":"squashfs","use%":"100%"}]}]}`, &mounts)
	volumes := parseLinuxVolumes(mounts)
	if len(volumes) != 1 || volumes[0].(map[string]any)["used_percent"] != float64(75) {
		t.Fatalf("unexpected volumes: %#v", volumes)
	}
}

func TestLinuxNetworkNormalization(t *testing.T) {
	var interfaces any
	mustJSON(t, `[{"ifname":"eth0","operstate":"UP","address":"aa:bb:cc:dd:ee:ff","flags":["UP"],"addr_info":[{"family":"inet","local":"192.0.2.1","prefixlen":24,"scope":"global"}]}]`, &interfaces)
	normalized := parseLinuxInterfaces(interfaces)
	if len(normalized) != 1 || normalized[0]["name"] != "eth0" || normalized[0]["state"] != "active" {
		t.Fatalf("unexpected interfaces: %#v", normalized)
	}

	var resolved any
	mustJSON(t, `[{"servers":null},{"servers":[{"addressString":"192.0.2.53"},{"addressString":"192.0.2.53"}]}]`, &resolved)
	dns := parseLinuxResolvedDNS(resolved)
	if len(dns) != 1 || dns[0] != "192.0.2.53" {
		t.Fatalf("unexpected DNS: %#v", dns)
	}
	dns = parseLinuxResolvedDNSText("Global:\nLink 2 (eth0): 192.0.2.53 2001:db8::53\n")
	if len(dns) != 2 || dns[0] != "192.0.2.53" || dns[1] != "2001:db8::53" {
		t.Fatalf("unexpected text DNS: %#v", dns)
	}
}

func TestLinuxJournalNormalization(t *testing.T) {
	events := parseLinuxJournal(`{"__REALTIME_TIMESTAMP":"1787120613648330","PRIORITY":"2","_SYSTEMD_UNIT":"example.service","MESSAGE":"failed"}`+"\n", 10)
	if len(events) != 1 || events[0]["severity"] != "critical" || events[0]["source"] != "example.service" || events[0]["timestamp"] != "2026-08-19T06:23:33.64833Z" {
		t.Fatalf("unexpected events: %#v", events)
	}
}

func mustJSON(t *testing.T, text string, target any) {
	t.Helper()
	if err := json.Unmarshal([]byte(text), target); err != nil {
		t.Fatal(err)
	}
}
