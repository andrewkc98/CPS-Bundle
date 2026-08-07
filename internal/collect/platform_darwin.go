//go:build darwin

package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
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
	data := map[string]any{"hostname": host, "architecture": runtime.GOARCH}
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
	data := map[string]any{}
	if root, ok := value.(map[string]any); ok {
		if records, ok := root["SPHardwareDataType"].([]any); ok && len(records) > 0 {
			if item, ok := records[0].(map[string]any); ok {
				data["cpu_model"] = item["chip_type"]
				data["firmware"] = item["boot_rom_version"]
			}
		}
	}
	if logical, err := runText(ctx, "sysctl", "-n", "hw.logicalcpu"); err == nil {
		if count, parseErr := strconv.Atoi(strings.TrimSpace(logical)); parseErr == nil {
			data["cpu_logical_count"] = count
		}
	}
	if memory, err := runText(ctx, "sysctl", "-n", "hw.memsize"); err == nil {
		if bytes, parseErr := strconv.ParseInt(strings.TrimSpace(memory), 10, 64); parseErr == nil {
			data["memory_bytes"] = bytes
		}
	}
	return data, []model.Evidence{{Name: "evidence/hardware-system_profiler.json", Content: []byte(limit(raw, 4<<20))}}, nil, nil, false, nil
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
	diskInfo, _ := runText(ctx, "diskutil", "info", "/")
	df, dfErr := runText(ctx, "df", "-kP")
	warnings := []string{}
	if dfErr != nil {
		warnings = append(warnings, "filesystem capacity unavailable")
	}
	health := macDiskHealth(diskInfo)
	devices := []map[string]any{{"description": "root physical store", "health": health}}
	evidence := limit(text+"\n\n--- diskutil info / ---\n"+diskInfo+"\n\n--- df -kP ---\n"+df, 6<<20)
	return map[string]any{"devices": devices, "volumes": parseMacVolumes(df), "health": health}, []model.Evidence{{Name: "evidence/storage-diskutil.txt", Content: []byte(evidence)}}, warnings, missing, false, nil
}
func macNetwork(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
	interfaces, err := runText(ctx, "ifconfig")
	if err != nil {
		return map[string]any{"interfaces": []any{}, "routes": []any{}, "dns": []any{}}, nil, nil, nil, false, err
	}
	routes, _ := runText(ctx, "netstat", "-rn")
	dns, _ := runText(ctx, "scutil", "--dns")
	return map[string]any{"interfaces": parseMacInterfaces(interfaces), "routes": []map[string]any{{"raw": routes}}, "dns": parseMacDNS(dns)}, []model.Evidence{{Name: "evidence/network-config.txt", Content: []byte(limit(interfaces+"\n"+routes+"\n"+dns, 6<<20))}}, nil, nil, false, nil
}
func macErrors(ctx context.Context, opts model.Options) (any, []model.Evidence, []string, []string, bool, error) {
	lookback := macLogLookback(opts.Since)
	text, err := runText(ctx, "log", "show", "--style", "json", "--last", lookback, "--predicate", "messageType == error OR messageType == fault")
	if err != nil {
		return []map[string]any{}, nil, nil, nil, false, fmt.Errorf("log show failed for %s: %w", lookback, err)
	}
	events := parseMacLog(text, opts.MaxEvents)
	return events, []model.Evidence{{Name: "evidence/errors-unified-log.jsonl", Content: []byte(limit(text, 8<<20))}}, nil, nil, len(events) >= opts.MaxEvents, nil
}

func macLogLookback(duration time.Duration) string {
	hours := int((duration + time.Hour - 1) / time.Hour)
	if hours < 1 {
		hours = 1
	}
	return fmt.Sprintf("%dh", hours)
}

func parseMacLog(text string, limit int) []map[string]any {
	var records []map[string]any
	if json.Unmarshal([]byte(text), &records) != nil {
		for _, line := range strings.Split(text, "\n") {
			var record map[string]any
			if json.Unmarshal([]byte(line), &record) == nil {
				records = append(records, record)
			}
		}
	}
	events := make([]map[string]any, 0, min(len(records), limit))
	for _, record := range records {
		severity := strings.ToLower(fmt.Sprint(record["messageType"]))
		if severity == "fault" {
			severity = "critical"
		} else {
			severity = "error"
		}
		source := record["subsystem"]
		if source == nil || fmt.Sprint(source) == "" {
			source = record["process"]
		}
		events = append(events, map[string]any{"timestamp": normalizeMacTimestamp(record["timestamp"]), "severity": severity, "source": source, "native_code": record["category"], "message": record["eventMessage"]})
		if len(events) >= limit {
			break
		}
	}
	return events
}

func normalizeMacTimestamp(value any) any {
	text := strings.TrimSpace(fmt.Sprint(value))
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999-0700", "2006-01-02 15:04:05.999999-0700"} {
		if parsed, err := time.Parse(layout, text); err == nil {
			return parsed.UTC().Format(time.RFC3339Nano)
		}
	}
	return value
}

func macDiskHealth(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(strings.ToLower(line), "smart status") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		value := strings.ToLower(strings.TrimSpace(parts[1]))
		if value == "verified" {
			return "healthy"
		}
		if strings.Contains(value, "fail") {
			return "critical"
		}
	}
	return "unknown"
}

func parseMacVolumes(text string) []any {
	volumes := []any{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || !strings.HasPrefix(fields[0], "/dev/") {
			continue
		}
		sizeKB, sizeErr := strconv.ParseInt(fields[1], 10, 64)
		freeKB, freeErr := strconv.ParseInt(fields[3], 10, 64)
		used, usedErr := strconv.ParseFloat(strings.TrimSuffix(fields[4], "%"), 64)
		if sizeErr != nil || freeErr != nil || usedErr != nil {
			continue
		}
		volumes = append(volumes, map[string]any{"filesystem": fields[0], "mount_point": strings.Join(fields[5:], " "), "size_bytes": sizeKB * 1024, "free_bytes": freeKB * 1024, "used_percent": used, "health": "unknown"})
	}
	return volumes
}

func parseMacInterfaces(text string) []map[string]any {
	interfaces := []map[string]any{}
	var current map[string]any
	for _, line := range strings.Split(text, "\n") {
		if line != "" && line[0] != '\t' && line[0] != ' ' && strings.Contains(line, ": flags=") {
			name := strings.SplitN(line, ":", 2)[0]
			current = map[string]any{"name": name, "state": "unknown", "addresses": []map[string]any{}}
			interfaces = append(interfaces, current)
			continue
		}
		if current == nil {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "ether":
			current["mac_address"] = fields[1]
		case "inet":
			current["addresses"] = append(current["addresses"].([]map[string]any), map[string]any{"family": "ipv4", "address": fields[1]})
		case "inet6":
			current["addresses"] = append(current["addresses"].([]map[string]any), map[string]any{"family": "ipv6", "address": fields[1]})
		case "status:":
			current["state"] = fields[1]
		}
	}
	return interfaces
}

func parseMacDNS(text string) []string {
	servers := []string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.HasPrefix(fields[0], "nameserver[") || fields[1] != ":" {
			continue
		}
		if !seen[fields[2]] {
			servers = append(servers, fields[2])
			seen[fields[2]] = true
		}
	}
	return servers
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
