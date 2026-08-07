//go:build linux

package collect

import (
	"context"
	"encoding/json"
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
		commandCollector("hardware", "procfs+sysfs", 30*time.Second, linuxHardware),
		commandCollector("operating_system", "os-release+uname", 30*time.Second, linuxOS),
		commandCollector("storage", "lsblk+sysfs", 45*time.Second, func(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
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
	return map[string]any{"hostname": host, "architecture": runtime.GOARCH, "manufacturer": readTrim("/sys/class/dmi/id/sys_vendor"), "model": readTrim("/sys/class/dmi/id/product_name"), "serial": readTrim("/sys/class/dmi/id/product_serial"), "virtualization": readTrim("/sys/class/dmi/id/product_version")}, nil, nil, nil, false, nil
}

func linuxHardware(context.Context) (any, []model.Evidence, []string, []string, bool, error) {
	modelName := ""
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "model name") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					modelName = strings.TrimSpace(parts[1])
				}
				break
			}
		}
	}
	mem := map[string]any{}
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Fields(line)
			if len(parts) >= 2 && (parts[0] == "MemTotal:" || parts[0] == "MemAvailable:") {
				n, _ := strconv.ParseInt(parts[1], 10, 64)
				mem[strings.TrimSuffix(parts[0], ":")] = n * 1024
			}
		}
	}
	uptime := 0.0
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		uptime, _ = strconv.ParseFloat(strings.Fields(string(data))[0], 64)
	}
	return map[string]any{"cpu_model": modelName, "cpu_logical_count": runtime.NumCPU(), "memory_bytes": mem, "uptime_seconds": uptime, "firmware": readTrim("/sys/class/dmi/id/bios_version")}, nil, nil, nil, false, nil
}

func linuxOS(context.Context) (any, []model.Evidence, []string, []string, bool, error) {
	values := map[string]any{"family": "linux", "kernel": strings.TrimSpace(mustText("uname", "-r")), "architecture": runtime.GOARCH, "reboot_pending": fileExists("/var/run/reboot-required"), "last_updates": linuxUpdateHistory()}
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
	data := map[string]any{"devices": value, "volumes": []any{}, "health": "unknown"}
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
	return data, []model.Evidence{{Name: "evidence/storage-lsblk.json", Content: []byte(limit(raw, 2<<20))}}, nil, missing, false, nil
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
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "nameserver" {
				dns = append(dns, fields[1])
			}
		}
	}
	return map[string]any{"interfaces": interfaces, "routes": routes, "dns": dns}, []model.Evidence{{Name: "evidence/network-ip.txt", Content: []byte(limit(rawAddr+"\n"+rawRoute, 2<<20))}}, warnings, nil, false, nil
}

func linuxErrors(ctx context.Context, opts model.Options) (any, []model.Evidence, []string, []string, bool, error) {
	text, err := runText(ctx, "journalctl", "--no-pager", "--utc", "-p", "err..alert", "--since", "-"+opts.Since.String(), "-o", "json")
	if err != nil {
		return []map[string]any{}, nil, []string{"journalctl unavailable"}, nil, false, err
	}
	var events []map[string]any
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var raw map[string]any
		if json.Unmarshal([]byte(line), &raw) != nil {
			continue
		}
		level := "error"
		if raw["PRIORITY"] == float64(2) {
			level = "critical"
		}
		events = append(events, map[string]any{"timestamp": raw["__REALTIME_TIMESTAMP"], "severity": level, "source": raw["SYSLOG_IDENTIFIER"], "native_code": raw["ERRNO"], "message": raw["MESSAGE"]})
		if len(events) >= opts.MaxEvents {
			break
		}
	}
	return events, []model.Evidence{{Name: "evidence/errors-journal.jsonl", Content: []byte(limit(text, 8<<20))}}, nil, nil, len(events) >= opts.MaxEvents, nil
}

func linuxSoftware(ctx context.Context, opts model.Options) (any, []model.Evidence, []string, []string, bool, error) {
	var text string
	var err error
	if _, lookErr := lookupCommand("dpkg-query"); lookErr == nil {
		text, err = runText(ctx, "dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n")
	} else if _, lookErr := lookupCommand("rpm"); lookErr == nil {
		text, err = runText(ctx, "rpm", "-qa", "--qf", "{NAME}\t{VERSION}-{RELEASE}\t{ARCH}\n")
	} else {
		return []map[string]any{}, nil, []string{"dpkg-query/rpm"}, nil, false, nil
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
	return apps, nil, missing, nil, false, nil
}

func readTrim(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }
func limit(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "\n[truncated]\n"
}
