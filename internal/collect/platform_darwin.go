//go:build darwin

package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"cps-bundle/internal/model"
)

func platformCollectors(opts model.Options) []Collector {
	return []Collector{
		commandCollector("identity", "system_profiler", 60*time.Second, macIdentity),
		commandCollector("hardware", "system_profiler+sysctl", 60*time.Second, macHardware),
		commandCollector("operating_system", "sw_vers+softwareupdate", 60*time.Second, macOS),
		commandCollector("storage", "diskutil", 60*time.Second, func(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
			return macStorage(ctx, opts)
		}),
		commandCollector("network", "networksetup+scutil", 60*time.Second, macNetwork),
		commandCollector("recent_errors", "unified log", 120*time.Second, func(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
			return macErrors(ctx, opts)
		}),
		commandCollector("software", "system_profiler+brew", 120*time.Second, func(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
			return macSoftware(ctx, opts)
		}),
	}
}

func macJSON(ctx context.Context, tool string, args ...string) (any, string, error) {
	return runJSON(ctx, tool, args...)
}

func macIdentity(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
	value, _, err := macJSON(ctx, "system_profiler", "SPHardwareDataType", "-json")
	if err != nil {
		return map[string]any{}, nil, nil, nil, false, err
	}
	host, _ := os.Hostname()
	data := map[string]any{"hostname": host, "architecture": runtime.GOARCH, "hardware": value}
	if root, ok := value.(map[string]any); ok {
		if records, ok := root["SPHardwareDataType"].([]any); ok && len(records) > 0 {
			if item, ok := records[0].(map[string]any); ok {
				data["model"] = item["machine_name"]
				data["serial"] = item["serial_number"]
				data["manufacturer"] = "Apple"
			}
		}
	}
	return data, nil, nil, nil, false, nil
}
func macHardware(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
	value, raw, err := macJSON(ctx, "system_profiler", "SPHardwareDataType", "-json")
	if err != nil {
		return map[string]any{}, nil, nil, nil, false, err
	}
	return map[string]any{"hardware": value}, []model.Evidence{{Name: "evidence/hardware-system_profiler.json", Content: []byte(limit(raw, 4<<20))}}, nil, nil, false, nil
}
func macOS(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
	name, err := runText(ctx, "sw_vers", "-productName")
	if err != nil {
		return map[string]any{}, nil, nil, nil, false, err
	}
	version, _ := runText(ctx, "sw_vers", "-productVersion")
	build, _ := runText(ctx, "sw_vers", "-buildVersion")
	history, _ := runText(ctx, "softwareupdate", "--history")
	return map[string]any{"family": "darwin", "name": strings.TrimSpace(name), "version": strings.TrimSpace(version), "build": strings.TrimSpace(build), "kernel": strings.TrimSpace(mustText("uname", "-r")), "last_updates": strings.TrimSpace(limit(history, 2<<20)), "reboot_pending": false}, nil, nil, nil, false, nil
}
func macStorage(ctx context.Context, opts model.Options) (any, []model.Evidence, []string, []string, bool, error) {
	text, err := runText(ctx, "diskutil", "list")
	if err != nil {
		return map[string]any{"devices": []any{}, "volumes": []any{}, "health": "unavailable"}, nil, nil, nil, false, err
	}
	missing := []string{}
	if opts.NoEnrichers {
		missing = append(missing, "smartctl")
	}
	return map[string]any{"devices": []map[string]any{{"description": "diskutil listing", "health": "unknown"}}, "volumes": []any{}, "health": "unknown"}, []model.Evidence{{Name: "evidence/storage-diskutil.txt", Content: []byte(limit(text, 4<<20))}}, nil, missing, false, nil
}
func macNetwork(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
	interfaces, err := runText(ctx, "ifconfig")
	if err != nil {
		return map[string]any{"interfaces": []any{}, "routes": []any{}, "dns": []any{}}, nil, nil, nil, false, err
	}
	routes, _ := runText(ctx, "netstat", "-rn")
	dns, _ := runText(ctx, "scutil", "--dns")
	return map[string]any{"interfaces": []map[string]any{{"raw": interfaces}}, "routes": []map[string]any{{"raw": routes}}, "dns": []map[string]any{{"raw": dns}}}, []model.Evidence{{Name: "evidence/network-config.txt", Content: []byte(limit(interfaces+"\n"+routes+"\n"+dns, 6<<20))}}, nil, nil, false, nil
}
func macErrors(ctx context.Context, opts model.Options) (any, []model.Evidence, []string, []string, bool, error) {
	text, err := runText(ctx, "log", "show", "--style", "json", "--last", opts.Since.String(), "--predicate", "messageType == 'Error' OR messageType == 'Fault'")
	if err != nil {
		return []map[string]any{}, nil, nil, nil, false, err
	}
	var events []map[string]any
	for _, line := range strings.Split(text, "\n") {
		var raw map[string]any
		if json.Unmarshal([]byte(line), &raw) == nil {
			events = append(events, map[string]any{"timestamp": raw["timestamp"], "severity": "error", "source": raw["process"], "message": raw["eventMessage"]})
			if len(events) >= opts.MaxEvents {
				break
			}
		}
	}
	return events, []model.Evidence{{Name: "evidence/errors-unified-log.jsonl", Content: []byte(limit(text, 8<<20))}}, nil, nil, len(events) >= opts.MaxEvents, nil
}
func macSoftware(ctx context.Context, opts model.Options) (any, []model.Evidence, []string, []string, bool, error) {
	value, raw, err := macJSON(ctx, "system_profiler", "SPApplicationsDataType", "-json")
	if err != nil {
		return []map[string]any{}, nil, nil, nil, false, err
	}
	apps := []map[string]any{}
	if root, ok := value.(map[string]any); ok {
		if records, ok := root["SPApplicationsDataType"].([]any); ok {
			for _, record := range records {
				if item, ok := record.(map[string]any); ok {
					name := item["_name"]
					if name == nil {
						name = item["name"]
					}
					apps = append(apps, map[string]any{"name": name, "version": item["version"], "publisher": item["obtained_from"], "install_scope": "system", "source": "system_profiler", "architecture": item["architecture"]})
				}
			}
		}
	}
	missing := []string{}
	if opts.NoEnrichers {
		missing = append(missing, "brew")
	} else if _, lookErr := lookupCommand("brew"); lookErr == nil {
		if extra, extraErr := runText(ctx, "brew", "list", "--versions"); extraErr == nil {
			for _, line := range strings.Split(extra, "\n") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					apps = append(apps, map[string]any{"name": parts[0], "version": parts[1], "install_scope": "user", "source": "homebrew"})
				}
			}
		}
	} else {
		missing = append(missing, "brew")
	}
	return apps, []model.Evidence{{Name: "evidence/software-system_profiler.json", Content: []byte(limit(raw, 12<<20))}}, nil, missing, false, nil
}
func limit(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + fmt.Sprintln("[truncated]")
}
