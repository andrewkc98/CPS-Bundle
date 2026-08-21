//go:build windows

package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	"cps-bundle/internal/model"
)

func platformCollectors(opts model.Options) []Collector {
	return []Collector{
		commandCollector("identity", "CIM", 45*time.Second, windowsIdentity),
		commandCollector("hardware", "CIM", 45*time.Second, windowsHardware),
		commandCollector("operating_system", "CIM+hotfix", 60*time.Second, windowsOS),
		commandCollector("storage", "Storage cmdlets", 60*time.Second, func(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
			return windowsStorage(ctx, opts)
		}),
		commandCollector("network", "NetTCPIP cmdlets", 45*time.Second, windowsNetwork),
		commandCollector("recent_errors", "Windows Event Log", 120*time.Second, func(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
			return windowsErrors(ctx, opts)
		}),
		commandCollector("software", "Uninstall registry", 120*time.Second, windowsSoftware),
	}
}

func powershell(ctx context.Context, script string) (any, string, error) {
	text, err := runText(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if err != nil {
		return nil, text, err
	}
	var value any
	if err := json.Unmarshal([]byte(text), &value); err != nil {
		return nil, text, err
	}
	return value, text, nil
}

func windowsIdentity(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
	value, _, err := powershell(ctx, "$cs=Get-CimInstance Win32_ComputerSystem; $bios=Get-CimInstance Win32_BIOS; [pscustomobject]@{hostname=$cs.Name;manufacturer=$cs.Manufacturer;model=$cs.Model;username=$cs.UserName;serial=$bios.SerialNumber} | ConvertTo-Json -Compress")
	if err != nil {
		return map[string]any{}, nil, nil, nil, false, err
	}
	data, err := normalizeWindowsIdentity(value, runtime.GOARCH)
	if err != nil {
		return map[string]any{}, nil, nil, nil, false, err
	}
	return data, nil, nil, nil, false, nil
}

func windowsHardware(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
	value, _, err := powershell(ctx, "$cpu=Get-CimInstance Win32_Processor | Select-Object -First 1 Name,NumberOfLogicalProcessors; $mem=Get-CimInstance Win32_ComputerSystem | Select-Object TotalPhysicalMemory; [pscustomobject]@{cpu_model=$cpu.Name;cpu_logical_count=$cpu.NumberOfLogicalProcessors;memory_bytes=[int64]$mem.TotalPhysicalMemory} | ConvertTo-Json -Compress")
	if err != nil {
		return map[string]any{}, nil, nil, nil, false, err
	}
	data, ok := value.(map[string]any)
	if !ok {
		return map[string]any{}, nil, nil, nil, false, fmt.Errorf("Windows hardware response is not an object")
	}
	return data, nil, nil, nil, false, nil
}

func windowsOS(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
	value, _, err := powershell(ctx, "$os=Get-CimInstance Win32_OperatingSystem; $hotfix=Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 25 HotFixID,@{n='installed_at';e={if ($_.InstalledOn) {$_.InstalledOn.ToUniversalTime().ToString('o')} else {$null}}},Description; [pscustomobject]@{family='windows';name=$os.Caption;version=$os.Version;build=$os.BuildNumber;kernel=$os.Version;last_updates=$hotfix;reboot_pending=Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'} | ConvertTo-Json -Depth 5 -Compress")
	if err != nil {
		return map[string]any{}, nil, nil, nil, false, err
	}
	data, ok := value.(map[string]any)
	if !ok {
		return map[string]any{}, nil, nil, nil, false, fmt.Errorf("Windows operating-system response is not an object")
	}
	return data, nil, nil, nil, false, nil
}

func windowsStorage(ctx context.Context, opts model.Options) (any, []model.Evidence, []string, []string, bool, error) {
	value, raw, err := powershell(ctx, "$devices=Get-PhysicalDisk | Select-Object FriendlyName,SerialNumber,MediaType,Size,HealthStatus,OperationalStatus,BusType,Usage; $volumes=Get-Volume | Where-Object DriveLetter | ForEach-Object {[pscustomobject]@{drive_letter=$_.DriveLetter;filesystem=$_.FileSystem;label=$_.FileSystemLabel;size_bytes=$_.Size;free_bytes=$_.SizeRemaining;used_percent=if ($_.Size -gt 0) {[math]::Round(100*(1-($_.SizeRemaining/$_.Size)),2)} else {$null};health=$_.HealthStatus;operational_status=$_.OperationalStatus}}; [pscustomobject]@{devices=$devices;volumes=$volumes;health='reported-by-storage-api'} | ConvertTo-Json -Depth 4 -Compress")
	missing := []string{}
	if opts.NoEnrichers {
		missing = append(missing, "StorageReliabilityCounter")
	}
	if err != nil {
		return map[string]any{"devices": []any{}, "volumes": []any{}, "health": "unavailable"}, nil, nil, missing, false, err
	}
	evidence, truncated := windowsEvidence("evidence/storage-powershell.json", raw, 8<<20)
	return normalizeWindowsStorage(value), evidence, nil, missing, truncated, nil
}

func windowsNetwork(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
	value, raw, err := powershell(ctx, "$a=Get-NetIPConfiguration; $r=Get-NetRoute; $d=Get-DnsClientServerAddress; [pscustomobject]@{config=$a;routes=$r;dns=$d} | ConvertTo-Json -Depth 6 -Compress")
	if err != nil {
		return map[string]any{"interfaces": []any{}, "routes": []any{}, "dns": []any{}}, nil, nil, nil, false, err
	}
	evidence, truncated := windowsEvidence("evidence/network-powershell.json", raw, 8<<20)
	return normalizeWindowsNetwork(value), evidence, nil, nil, truncated, nil
}

func windowsErrors(ctx context.Context, opts model.Options) (any, []model.Evidence, []string, []string, bool, error) {
	script := fmt.Sprintf("$since=(Get-Date).AddHours(-%.3f); $events=Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2; StartTime=$since} -ErrorAction SilentlyContinue | Select-Object -First %d @{n='timestamp';e={$_.TimeCreated.ToUniversalTime().ToString('o')}},ProviderName,Id,Level,Message; @($events) | ConvertTo-Json -Depth 4 -Compress", opts.Since.Hours(), opts.MaxEvents)
	value, raw, err := powershellEvents(ctx, script)
	if err != nil {
		return []map[string]any{}, nil, nil, nil, false, err
	}
	evidence, truncated := windowsEvidence("evidence/errors-eventlog.json", raw, 8<<20)
	return normalizeWindowsEvents(value), evidence, nil, nil, truncated, nil
}

func windowsSoftware(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
	value, raw, err := powershell(ctx, "$paths='HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object DisplayName | Select-Object @{n='name';e={$_.DisplayName}},@{n='version';e={$_.DisplayVersion}},@{n='publisher';e={$_.Publisher}},@{n='install_date';e={$_.InstallDate}} | ConvertTo-Json -Depth 4 -Compress")
	if err != nil {
		return []map[string]any{}, nil, nil, nil, false, err
	}
	evidence, truncated := windowsEvidence("evidence/software-registry.json", raw, 8<<20)
	return normalizeWindowsSoftware(value), evidence, nil, nil, truncated, nil
}

func powershellEvents(ctx context.Context, script string) (any, string, error) {
	text, err := runText(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if err != nil {
		return nil, text, err
	}
	value, err := parseWindowsEventsOutput(text)
	if err != nil {
		return nil, text, err
	}
	return value, text, nil
}

func parseWindowsEventsOutput(text string) (any, error) {
	if strings.TrimSpace(text) == "" {
		return []any{}, nil
	}
	var value any
	if err := json.Unmarshal([]byte(text), &value); err != nil {
		return nil, err
	}
	return value, nil
}

func normalizeWindowsIdentity(value any, architecture string) (map[string]any, error) {
	data, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("Windows identity response is not an object")
	}
	if serial, ok := data["serial"].(string); ok && (strings.EqualFold(strings.TrimSpace(serial), "to be filled by o.e.m.") || strings.TrimSpace(serial) == "") {
		data["serial"] = nil
	}
	data["architecture"] = architecture
	return data, nil
}

func windowsArray(value any) []any {
	if value == nil {
		return []any{}
	}
	if values, ok := value.([]any); ok {
		return values
	}
	return []any{value}
}

func normalizeWindowsStorage(value any) map[string]any {
	data, ok := value.(map[string]any)
	if !ok {
		return map[string]any{"devices": []any{}, "volumes": []any{}, "health": "reported-by-storage-api"}
	}
	devices := make([]any, 0)
	for _, item := range windowsArray(data["devices"]) {
		if disk, ok := item.(map[string]any); ok {
			devices = append(devices, map[string]any{
				"name":        firstWindowsValue(disk, "FriendlyName", "friendly_name", "name"),
				"description": firstWindowsValue(disk, "FriendlyName", "friendly_name", "Description", "description"),
				"serial":      firstWindowsValue(disk, "SerialNumber", "serial_number", "serial"),
				"media_type":  windowsEnum(firstWindowsValue(disk, "MediaType", "media_type")),
				"size_bytes":  firstWindowsValue(disk, "Size", "size_bytes"),
				"health":      windowsEnum(firstWindowsValue(disk, "HealthStatus", "health")),
			})
		}
	}
	volumes := make([]any, 0)
	for _, item := range windowsArray(data["volumes"]) {
		if volume, ok := item.(map[string]any); ok {
			drive := fmt.Sprint(firstWindowsValue(volume, "drive_letter", "DriveLetter"))
			if drive == "<nil>" {
				drive = ""
			}
			mountPoint := ""
			if drive != "" {
				mountPoint = strings.TrimSuffix(drive, ":") + ":\\"
			}
			volumes = append(volumes, map[string]any{
				"filesystem":      drive,
				"mount_point":     mountPoint,
				"filesystem_type": windowsEnum(firstWindowsValue(volume, "filesystem", "FileSystem")),
				"size_bytes":      firstWindowsValue(volume, "size_bytes", "Size"),
				"free_bytes":      firstWindowsValue(volume, "free_bytes", "SizeRemaining"),
				"used_percent":    windowsUsedPercent(volume),
				"health":          windowsEnum(firstWindowsValue(volume, "health", "HealthStatus")),
			})
		}
	}
	return map[string]any{"devices": devices, "volumes": volumes, "health": data["health"]}
}

func normalizeWindowsNetwork(value any) map[string]any {
	data, ok := value.(map[string]any)
	if !ok {
		return map[string]any{"interfaces": []any{}, "routes": []any{}, "dns": []any{}}
	}
	interfaces := make([]any, 0)
	for _, item := range windowsArray(data["config"]) {
		if config, ok := item.(map[string]any); ok {
			interfaces = append(interfaces, map[string]any{
				"name":        firstWindowsValue(config, "InterfaceAlias", "interface_alias", "name"),
				"state":       windowsNetworkState(config),
				"mac_address": windowsConfigMAC(config),
				"addresses":   windowsConfigAddresses(config),
			})
		}
	}
	routes := make([]any, 0)
	for _, item := range windowsArray(data["routes"]) {
		if route, ok := item.(map[string]any); ok {
			routes = append(routes, map[string]any{
				"destination": firstWindowsValue(route, "DestinationPrefix", "destination"),
				"gateway":     firstWindowsValue(route, "NextHop", "gateway"),
				"interface":   firstWindowsValue(route, "InterfaceAlias", "interface"),
				"metric":      firstWindowsValue(route, "RouteMetric", "metric"),
				"protocol":    windowsEnum(firstWindowsValue(route, "Protocol", "protocol")),
			})
		}
	}
	return map[string]any{"interfaces": interfaces, "routes": routes, "dns": windowsDNS(data["dns"])}
}

func windowsUsedPercent(volume map[string]any) any {
	if used := firstWindowsValue(volume, "used_percent"); used != nil {
		return used
	}
	size, sizeOK := windowsFloat(firstWindowsValue(volume, "size_bytes", "Size"))
	free, freeOK := windowsFloat(firstWindowsValue(volume, "free_bytes", "SizeRemaining"))
	if !sizeOK || !freeOK || size <= 0 {
		return nil
	}
	return float64(int((100*(1-free/size))*100+0.5)) / 100
}

func windowsFloat(value any) (float64, bool) {
	switch number := value.(type) {
	case float64:
		return number, true
	case float32:
		return float64(number), true
	case int:
		return float64(number), true
	case int64:
		return float64(number), true
	case json.Number:
		parsed, err := number.Float64()
		return parsed, err == nil
	default:
		return 0, false
	}
}

func windowsEnum(value any) string {
	text := strings.TrimSpace(fmt.Sprint(value))
	if text == "" || text == "<nil>" {
		return "unknown"
	}
	return strings.ToLower(text)
}

func windowsNetworkState(config map[string]any) any {
	value := firstWindowsValue(config, "Status", "status")
	if adapter, ok := firstWindowsValue(config, "NetAdapter", "net_adapter").(map[string]any); ok {
		value = firstWindowsValue(adapter, "Status", "status")
	}
	state := strings.ToLower(strings.TrimSpace(fmt.Sprint(value)))
	if state == "up" || state == "connected" {
		return "active"
	}
	return "inactive"
}

func windowsConfigMAC(config map[string]any) any {
	if adapter, ok := firstWindowsValue(config, "NetAdapter", "net_adapter").(map[string]any); ok {
		return firstWindowsValue(adapter, "MacAddress", "mac_address")
	}
	return firstWindowsValue(config, "MacAddress", "mac_address")
}

func windowsConfigAddresses(config map[string]any) []any {
	addresses := make([]any, 0)
	for _, family := range []struct{ key, name string }{{"IPv4Address", "ipv4"}, {"IPv6Address", "ipv6"}} {
		for _, item := range windowsArray(config[family.key]) {
			if address, ok := item.(map[string]any); ok {
				addresses = append(addresses, map[string]any{"family": family.name, "address": firstWindowsValue(address, "IPAddress", "address"), "prefix_length": firstWindowsValue(address, "PrefixLength", "prefix_length")})
			}
		}
	}
	return addresses
}

func windowsDNS(value any) []string {
	servers := make([]string, 0)
	seen := map[string]bool{}
	for _, item := range windowsArray(value) {
		if config, ok := item.(map[string]any); ok {
			for _, address := range windowsArray(firstWindowsValue(config, "ServerAddresses", "server_addresses")) {
				text, ok := address.(string)
				if ok && text != "" && !seen[text] {
					seen[text] = true
					servers = append(servers, text)
				}
			}
		}
	}
	return servers
}

func normalizeWindowsSoftware(value any) []map[string]any {
	items := make([]map[string]any, 0)
	for _, item := range windowsArray(value) {
		data, ok := item.(map[string]any)
		if !ok {
			continue
		}
		items = append(items, map[string]any{"name": data["name"], "version": data["version"], "publisher": firstWindowsValue(data, "publisher", "Publisher"), "install_date": firstWindowsValue(data, "install_date", "InstallDate"), "install_scope": "system", "source": "registry"})
	}
	return items
}

func firstWindowsValue(data map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := data[key]; ok {
			return value
		}
	}
	return nil
}

func windowsEvidence(name, raw string, max int) ([]model.Evidence, bool) {
	return []model.Evidence{{Name: name, Content: []byte(limit(raw, max))}}, len(raw) > max
}

func normalizeWindowsEvents(value any) []map[string]any {
	var rawItems []any
	if items, ok := value.([]any); ok {
		rawItems = items
	} else if value != nil {
		rawItems = []any{value}
	}
	items := make([]map[string]any, 0, len(rawItems))
	for _, item := range rawItems {
		if m, ok := item.(map[string]any); ok {
			severity := "error"
			if level, ok := windowsEventLevel(m["Level"]); ok && level == 1 {
				severity = "critical"
			}
			source := strings.TrimSpace(fmt.Sprint(m["ProviderName"]))
			if source == "" || source == "<nil>" {
				source = "unknown"
			}
			items = append(items, map[string]any{"timestamp": m["timestamp"], "severity": severity, "source": source, "native_code": m["Id"], "message": m["Message"]})
		}
	}
	return items
}

func windowsEventLevel(value any) (int, bool) {
	switch level := value.(type) {
	case float64:
		return int(level), level == 1 || level == 2
	case int:
		return level, level == 1 || level == 2
	case json.Number:
		parsed, err := level.Int64()
		return int(parsed), err == nil && (parsed == 1 || parsed == 2)
	default:
		return 0, false
	}
}
