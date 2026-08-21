//go:build linux

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
		commandCollector("identity", "procfs+dmi", 30*time.Second, linuxIdentity),
		commandCollector("hardware", "procfs+sysfs+lscpu", 30*time.Second, linuxHardware),
		commandCollector("operating_system", "os-release+uname", 30*time.Second, linuxOS),
		commandCollector("storage", "lsblk+findmnt+sysfs", 45*time.Second, func(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
			return linuxStorage(ctx, opts)
		}),
		commandCollector("network", "ip+resolver-config", 30*time.Second, linuxNetwork),
		commandCollector("recent_errors", "journalctl", 120*time.Second, func(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
			return linuxErrors(ctx, opts)
		}),
		commandCollector("software", "dpkg/rpm", 120*time.Second, func(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
			return linuxSoftware(ctx, opts)
		}),
	}
}

func linuxIdentity(context.Context) (any, []model.Evidence, []string, []string, bool, error) {
	host, _ := os.Hostname()
	data := map[string]any{"hostname": host, "architecture": runtime.GOARCH}
	for key, path := range map[string]string{"manufacturer": "/sys/class/dmi/id/sys_vendor", "model": "/sys/class/dmi/id/product_name", "serial": "/sys/class/dmi/id/product_serial", "virtualization": "/sys/class/dmi/id/product_version"} {
		if value := readTrim(path); value != "" {
			data[key] = value
		}
	}
	return data, nil, nil, nil, false, nil
}

func linuxHardware(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
	modelName := ""
	vendor := ""
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		modelName = linuxCPUInfoModel(string(data))
	}
	lscpuValue, lscpuRaw, lscpuErr := runJSON(ctx, "lscpu", "-J")
	if lscpuErr == nil {
		modelName, vendor = linuxCPUDescription(lscpuValue, modelName)
	}
	if modelName == "" || modelName == "-" {
		modelName = vendor
	}
	if modelName == "" || modelName == "-" {
		modelName = runtime.GOARCH
	}
	var memoryTotal, memoryAvailable int64
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Fields(line)
			if len(parts) >= 2 && (parts[0] == "MemTotal:" || parts[0] == "MemAvailable:") {
				n, _ := strconv.ParseInt(parts[1], 10, 64)
				if parts[0] == "MemTotal:" {
					memoryTotal = n * 1024
				} else {
					memoryAvailable = n * 1024
				}
			}
		}
	}
	uptime := 0.0
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		if fields := strings.Fields(string(data)); len(fields) > 0 {
			uptime, _ = strconv.ParseFloat(fields[0], 64)
		}
	}
	data := map[string]any{"cpu_model": modelName, "cpu_logical_count": runtime.NumCPU(), "memory_bytes": memoryTotal, "memory_available_bytes": memoryAvailable, "uptime_seconds": uptime, "firmware": readTrim("/sys/class/dmi/id/bios_version")}
	if vendor != "" {
		data["cpu_vendor"] = vendor
	}
	evidence := []model.Evidence{}
	if lscpuRaw != "" {
		evidence = append(evidence, model.Evidence{Name: "evidence/hardware-lscpu.json", Content: []byte(limit(lscpuRaw, 2<<20))})
	}
	return data, evidence, nil, nil, false, nil
}

func linuxOS(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
	kernel, _ := runText(ctx, "uname", "-r")
	values := map[string]any{"family": "linux", "kernel": strings.TrimSpace(kernel), "architecture": runtime.GOARCH, "reboot_pending": fileExists("/var/run/reboot-required"), "last_updates": linuxUpdateHistory()}
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				values[strings.ToLower(parts[0])] = strings.Trim(strings.TrimSpace(parts[1]), "\"")
			}
		}
	}
	return values, nil, nil, nil, false, nil
}

func linuxUpdateHistory() []string {
	var history []string
	for _, path := range []string{"/var/log/apt/history.log", "/var/log/dnf.rpm.log", "/var/log/yum.log"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		start := 0
		if len(lines) > 20 {
			start = len(lines) - 20
		}
		history = append(history, lines[start:]...)
	}
	return history
}

func linuxStorage(ctx context.Context, opts model.Options) (any, []model.Evidence, []string, []string, bool, error) {
	value, raw, err := runJSON(ctx, "lsblk", "-J", "-b", "-o", "NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,ROTA,MODEL,SERIAL")
	missing := []string{}
	if err != nil {
		return map[string]any{"devices": []any{}, "volumes": []any{}, "health": "unavailable"}, nil, nil, nil, false, err
	}
	volumes := []any{}
	warnings := []string{}
	findmntValue, findmntRaw, findmntErr := runJSON(ctx, "findmnt", "--json", "--bytes", "--real", "--output", "SOURCE,TARGET,FSTYPE,SIZE,USED,AVAIL,USE%")
	if findmntErr == nil {
		volumes = parseLinuxVolumes(findmntValue)
	} else {
		warnings = append(warnings, "filesystem capacity unavailable")
	}
	data := map[string]any{"devices": parseLinuxBlockDevices(value), "volumes": volumes, "health": "unknown"}
	if opts.NoEnrichers {
		missing = append(missing, "smartctl", "nvme")
	} else {
		if _, err := lookupCommand("smartctl"); err != nil {
			missing = append(missing, "smartctl")
		}
		if _, err := lookupCommand("nvme"); err != nil {
			missing = append(missing, "nvme")
		}
	}
	evidence := []model.Evidence{{Name: "evidence/storage-lsblk.json", Content: []byte(limit(raw, 2<<20))}}
	if findmntRaw != "" {
		evidence = append(evidence, model.Evidence{Name: "evidence/storage-findmnt.json", Content: []byte(limit(findmntRaw, 2<<20))})
	}
	return data, evidence, warnings, missing, false, nil
}

func linuxNetwork(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
	interfaces, rawAddr, err := runJSON(ctx, "ip", "-j", "addr")
	if err != nil {
		return map[string]any{"interfaces": []any{}, "routes": []any{}, "dns": []string{}}, nil, nil, nil, false, err
	}
	routes, rawRoute, routeErr := runJSON(ctx, "ip", "-j", "route")
	warnings := []string{}
	if routeErr != nil {
		warnings = append(warnings, "route configuration unavailable")
	}
	dns := []string{}
	resolvedRaw := ""
	if resolved, raw, resolvedErr := runJSON(ctx, "resolvectl", "dns", "--json=short"); resolvedErr == nil {
		dns = parseLinuxResolvedDNS(resolved)
		resolvedRaw = raw
	} else if text, textErr := runText(ctx, "resolvectl", "dns"); textErr == nil {
		dns = parseLinuxResolvedDNSText(text)
		resolvedRaw = text
	}
	if len(dns) == 0 {
		dns = parseLinuxResolvConf(readText("/etc/resolv.conf"))
	}
	return map[string]any{"interfaces": parseLinuxInterfaces(interfaces), "routes": parseLinuxRoutes(routes), "dns": dns}, []model.Evidence{{Name: "evidence/network-ip.txt", Content: []byte(limit(rawAddr+"\n"+rawRoute+"\n"+resolvedRaw, 2<<20))}}, warnings, nil, false, nil
}

func linuxErrors(ctx context.Context, opts model.Options) (any, []model.Evidence, []string, []string, bool, error) {
	text, err := runText(ctx, "journalctl", "--no-pager", "--utc", "-p", "err..alert", "--since", linuxJournalSince(opts.Since), "-n", strconv.Itoa(opts.MaxEvents), "-o", "json")
	if err != nil {
		return []map[string]any{}, nil, []string{"journalctl unavailable"}, nil, false, err
	}
	events := parseLinuxJournal(text, opts.MaxEvents)
	return events, []model.Evidence{{Name: "evidence/errors-journal.jsonl", Content: []byte(limit(text, 8<<20))}}, nil, nil, len(events) >= opts.MaxEvents, nil
}

func linuxSoftware(ctx context.Context, opts model.Options) (any, []model.Evidence, []string, []string, bool, error) {
	var text string
	var err error
	manager := ""
	for _, candidate := range linuxPackageManagerOrder(readText("/etc/os-release")) {
		if _, lookErr := lookupCommand(candidate); lookErr == nil {
			manager = candidate
			break
		}
	}
	switch manager {
	case "dpkg-query":
		text, err = runText(ctx, manager, "-W", "-f=${Package}\t${Version}\t${Architecture}\n")
	case "rpm":
		text, err = runText(ctx, manager, "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n")
	default:
		return []map[string]any{}, nil, nil, []string{"dpkg-query/rpm"}, false, nil
	}
	if err != nil {
		return []map[string]any{}, nil, nil, nil, false, err
	}
	var apps []map[string]any
	for _, line := range strings.Split(text, "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) >= 2 && parts[0] != "" {
			item := map[string]any{"name": parts[0], "version": parts[1], "install_scope": "system", "source": "package-manager"}
			if len(parts) > 2 {
				item["architecture"] = parts[2]
			}
			apps = append(apps, item)
		}
	}
	missing := []string{}
	for _, optional := range []string{"snap", "flatpak"} {
		if opts.NoEnrichers {
			missing = append(missing, optional)
			continue
		}
		if _, lookErr := lookupCommand(optional); lookErr != nil {
			missing = append(missing, optional)
			continue
		}
		if optional == "snap" {
			if extra, extraErr := runText(ctx, "snap", "list"); extraErr == nil {
				for _, line := range strings.Split(extra, "\n")[1:] {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						apps = append(apps, map[string]any{"name": parts[0], "version": parts[1], "install_scope": "system", "source": "snap"})
					}
				}
			}
		} else if extra, extraErr := runText(ctx, "flatpak", "list", "--columns=application,version,name"); extraErr == nil {
			for _, line := range strings.Split(extra, "\n") {
				parts := strings.Split(line, "\t")
				if len(parts) >= 2 {
					apps = append(apps, map[string]any{"name": parts[0], "version": parts[1], "install_scope": "system", "source": "flatpak"})
				}
			}
		}
	}
	return apps, nil, nil, missing, false, nil
}

func linuxJournalSince(duration time.Duration) string {
	seconds := int64((duration + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return "-" + strconv.FormatInt(seconds, 10) + "s"
}

func linuxPackageManagerOrder(osRelease string) []string {
	values := map[string]string{}
	for _, line := range strings.Split(osRelease, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			values[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.ToLower(strings.Trim(strings.TrimSpace(parts[1]), "\""))
		}
	}
	family := strings.Fields(values["id"] + " " + values["id_like"])
	for _, item := range family {
		switch item {
		case "rhel", "fedora", "centos", "rocky", "almalinux", "ol", "suse", "opensuse":
			return []string{"rpm", "dpkg-query"}
		}
	}
	return []string{"dpkg-query", "rpm"}
}

func readTrim(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
func readText(path string) string {
	data, _ := os.ReadFile(path)
	return string(data)
}
func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }

func linuxCPUDescription(value any, fallback string) (string, string) {
	modelName, vendor := fallback, ""
	root, _ := value.(map[string]any)
	items, _ := root["lscpu"].([]any)
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		field := strings.TrimSuffix(strings.TrimSpace(fmt.Sprint(item["field"])), ":")
		data := strings.TrimSpace(fmt.Sprint(item["data"]))
		switch field {
		case "Model name":
			if data != "" && data != "-" {
				modelName = data
			}
		case "Vendor ID":
			if data != "<nil>" {
				vendor = data
			}
		}
	}
	return modelName, vendor
}

func linuxCPUInfoModel(text string) string {
	for _, line := range strings.Split(text, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := strings.ToLower(strings.TrimSpace(parts[0])), strings.TrimSpace(parts[1])
		if (key == "model name" || key == "hardware") && value != "" {
			return value
		}
	}
	return ""
}

func parseLinuxBlockDevices(value any) []any {
	root, _ := value.(map[string]any)
	items, _ := root["blockdevices"].([]any)
	devices := []any{}
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		if fmt.Sprint(item["type"]) != "disk" {
			continue
		}
		name := strings.TrimSpace(fmt.Sprint(item["name"]))
		device := map[string]any{"name": "/dev/" + name, "description": stringValue(item["model"], name), "size_bytes": item["size"], "health": "unknown"}
		if rotational, ok := item["rota"].(bool); ok {
			device["rotational"] = rotational
			if rotational {
				device["media_type"] = "hdd"
			} else {
				device["media_type"] = "ssd"
			}
		}
		if serial := stringValue(item["serial"], ""); serial != "" {
			device["serial"] = serial
		}
		devices = append(devices, device)
	}
	return devices
}

func parseLinuxVolumes(value any) []any {
	root, _ := value.(map[string]any)
	items, _ := root["filesystems"].([]any)
	volumes := []any{}
	var walk func([]any)
	walk = func(entries []any) {
		for _, raw := range entries {
			item, _ := raw.(map[string]any)
			source, fstype := stringValue(item["source"], ""), stringValue(item["fstype"], "")
			if source != "" && !strings.HasPrefix(source, "/dev/loop") && fstype != "squashfs" && fstype != "iso9660" {
				volume := map[string]any{"filesystem": source, "mount_point": stringValue(item["target"], ""), "filesystem_type": fstype, "size_bytes": item["size"], "free_bytes": item["avail"], "health": "unknown"}
				if used := strings.TrimSuffix(stringValue(item["use%"], ""), "%"); used != "" {
					if percent, err := strconv.ParseFloat(used, 64); err == nil {
						volume["used_percent"] = percent
					}
				}
				volumes = append(volumes, volume)
			}
			if children, ok := item["children"].([]any); ok {
				walk(children)
			}
		}
	}
	walk(items)
	return volumes
}

func parseLinuxInterfaces(value any) []map[string]any {
	items, _ := value.([]any)
	interfaces := []map[string]any{}
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		state := "inactive"
		if strings.EqualFold(stringValue(item["operstate"], ""), "up") || stringSliceContains(item["flags"], "UP") {
			state = "active"
		}
		addresses := []map[string]any{}
		if entries, ok := item["addr_info"].([]any); ok {
			for _, entry := range entries {
				address, _ := entry.(map[string]any)
				family := stringValue(address["family"], "")
				if family == "inet" {
					family = "ipv4"
				} else if family == "inet6" {
					family = "ipv6"
				}
				addresses = append(addresses, map[string]any{"family": family, "address": address["local"], "prefix_length": address["prefixlen"], "scope": address["scope"]})
			}
		}
		normalized := map[string]any{"name": item["ifname"], "state": state, "addresses": addresses}
		if mac := stringValue(item["address"], ""); mac != "" && mac != "00:00:00:00:00:00" {
			normalized["mac_address"] = mac
		}
		interfaces = append(interfaces, normalized)
	}
	return interfaces
}

func parseLinuxRoutes(value any) []map[string]any {
	items, _ := value.([]any)
	routes := []map[string]any{}
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		route := map[string]any{"destination": item["dst"], "interface": item["dev"]}
		for source, target := range map[string]string{"gateway": "gateway", "prefsrc": "source", "metric": "metric", "protocol": "protocol"} {
			if item[source] != nil {
				route[target] = item[source]
			}
		}
		routes = append(routes, route)
	}
	return routes
}

func parseLinuxResolvedDNS(value any) []string {
	items, _ := value.([]any)
	servers, seen := []string{}, map[string]bool{}
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		entries, _ := item["servers"].([]any)
		for _, entry := range entries {
			server, _ := entry.(map[string]any)
			address := stringValue(server["addressString"], "")
			if address != "" && !seen[address] {
				servers, seen[address] = append(servers, address), true
			}
		}
	}
	return servers
}

func parseLinuxResolvedDNSText(text string) []string {
	servers, seen := []string{}, map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		for _, address := range strings.Fields(parts[1]) {
			if !seen[address] {
				servers, seen[address] = append(servers, address), true
			}
		}
	}
	return servers
}

func parseLinuxResolvConf(text string) []string {
	servers, seen := []string{}, map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" && !seen[fields[1]] {
			servers, seen[fields[1]] = append(servers, fields[1]), true
		}
	}
	return servers
}

func parseLinuxJournal(text string, maxEvents int) []map[string]any {
	events := []map[string]any{}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var raw map[string]any
		if json.Unmarshal([]byte(line), &raw) != nil {
			continue
		}
		priority, _ := strconv.Atoi(stringValue(raw["PRIORITY"], "3"))
		severity := "error"
		if priority <= 2 {
			severity = "critical"
		}
		source := firstString(raw, "SYSLOG_IDENTIFIER", "_SYSTEMD_UNIT", "_COMM", "_EXE")
		events = append(events, map[string]any{"timestamp": normalizeLinuxTimestamp(raw["__REALTIME_TIMESTAMP"]), "severity": severity, "source": source, "native_code": raw["ERRNO"], "message": raw["MESSAGE"]})
		if len(events) >= maxEvents {
			break
		}
	}
	return events
}

func normalizeLinuxTimestamp(value any) any {
	text := strings.TrimSpace(fmt.Sprint(value))
	if microseconds, err := strconv.ParseInt(text, 10, 64); err == nil {
		return time.UnixMicro(microseconds).UTC().Format(time.RFC3339Nano)
	}
	return value
}

func firstString(value map[string]any, keys ...string) string {
	for _, key := range keys {
		if text := stringValue(value[key], ""); text != "" {
			return text
		}
	}
	return "unknown"
}

func stringValue(value any, fallback string) string {
	if value == nil {
		return fallback
	}
	text := strings.TrimSpace(fmt.Sprint(value))
	if text == "" || text == "<nil>" || text == "-" {
		return fallback
	}
	return text
}

func stringSliceContains(value any, wanted string) bool {
	switch items := value.(type) {
	case []any:
		for _, item := range items {
			if fmt.Sprint(item) == wanted {
				return true
			}
		}
	case []string:
		for _, item := range items {
			if item == wanted {
				return true
			}
		}
	}
	return false
}
