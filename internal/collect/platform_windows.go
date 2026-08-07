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
	data, _ := value.(map[string]any)
	if serial, ok := data["serial"].(string); ok && (strings.EqualFold(strings.TrimSpace(serial), "to be filled by o.e.m.") || strings.TrimSpace(serial) == "") {
		data["serial"] = nil
	}
	data["architecture"] = runtime.GOARCH
	return data, nil, nil, nil, false, nil
}

func windowsHardware(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
	value, _, err := powershell(ctx, "$cpu=Get-CimInstance Win32_Processor | Select-Object -First 1 Name,NumberOfLogicalProcessors; $mem=Get-CimInstance Win32_ComputerSystem | Select-Object TotalPhysicalMemory; [pscustomobject]@{cpu_model=$cpu.Name;cpu_logical_count=$cpu.NumberOfLogicalProcessors;memory_bytes=[int64]$mem.TotalPhysicalMemory} | ConvertTo-Json -Compress")
	if err != nil {
		return map[string]any{}, nil, nil, nil, false, err
	}
	data, _ := value.(map[string]any)
	return data, nil, nil, nil, false, nil
}

func windowsOS(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
	value, _, err := powershell(ctx, "$os=Get-CimInstance Win32_OperatingSystem; $hotfix=Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 25 HotFixID,@{n='installed_at';e={if ($_.InstalledOn) {$_.InstalledOn.ToUniversalTime().ToString('o')} else {$null}}},Description; [pscustomobject]@{family='windows';name=$os.Caption;version=$os.Version;build=$os.BuildNumber;kernel=$os.Version;last_updates=$hotfix;reboot_pending=Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'} | ConvertTo-Json -Depth 5 -Compress")
	if err != nil {
		return map[string]any{}, nil, nil, nil, false, err
	}
	data, _ := value.(map[string]any)
	return data, nil, nil, nil, false, nil
}

func windowsStorage(ctx context.Context, opts model.Options) (any, []model.Evidence, []string, []string, bool, error) {
	value, raw, err := powershell(ctx, "$devices=Get-PhysicalDisk | Select-Object FriendlyName,SerialNumber,MediaType,Size,HealthStatus,OperationalStatus,BusType,Usage; $volumes=Get-Volume | Where-Object DriveLetter | ForEach-Object {[pscustomobject]@{drive_letter=$_.DriveLetter;filesystem=$_.FileSystem;label=$_.FileSystemLabel;size_bytes=$_.Size;free_bytes=$_.SizeRemaining;used_percent=if ($_.Size -gt 0) {[math]::Round(100*(1-($_.SizeRemaining/$_.Size)),2)} else {$null};health=$_.HealthStatus;operational_status=$_.OperationalStatus}}; [pscustomobject]@{devices=$devices;volumes=$volumes;health='reported-by-storage-api'} | ConvertTo-Json -Depth 4 -Compress")
	missing := []string{}
	if opts.NoEnrichers {
		missing = append(missing, "StorageReliabilityCounter")
	}
	if err != nil {
		return map[string]any{"devices": []any{}, "volumes": []any{}, "health": "unavailable"}, nil, missing, nil, false, err
	}
	if data, ok := value.(map[string]any); ok {
		return data, []model.Evidence{{Name: "evidence/storage-powershell.json", Content: []byte(raw)}}, missing, nil, false, nil
	}
	return map[string]any{"devices": value, "volumes": []any{}, "health": "reported-by-storage-api"}, []model.Evidence{{Name: "evidence/storage-powershell.json", Content: []byte(raw)}}, missing, nil, false, nil
}

func windowsNetwork(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
	value, raw, err := powershell(ctx, "$a=Get-NetIPConfiguration; $r=Get-NetRoute; $d=Get-DnsClientServerAddress; [pscustomobject]@{config=$a;routes=$r;dns=$d} | ConvertTo-Json -Depth 6 -Compress")
	if err != nil {
		return map[string]any{"interfaces": []any{}, "routes": []any{}, "dns": []any{}}, nil, nil, nil, false, err
	}
	if data, ok := value.(map[string]any); ok {
		return map[string]any{"interfaces": data["config"], "routes": data["routes"], "dns": data["dns"]}, []model.Evidence{{Name: "evidence/network-powershell.json", Content: []byte(raw)}}, nil, nil, false, nil
	}
	return map[string]any{"interfaces": []any{}, "routes": []any{}, "dns": []any{}}, []model.Evidence{{Name: "evidence/network-powershell.json", Content: []byte(raw)}}, nil, nil, false, nil
}

func windowsErrors(ctx context.Context, opts model.Options) (any, []model.Evidence, []string, []string, bool, error) {
	script := fmt.Sprintf("$since=(Get-Date).AddHours(-%.3f); Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2; StartTime=$since} -ErrorAction SilentlyContinue | Select-Object -First %d @{n='timestamp';e={$_.TimeCreated.ToUniversalTime().ToString('o')}},ProviderName,Id,LevelDisplayName,Message | ConvertTo-Json -Depth 4 -Compress", opts.Since.Hours(), opts.MaxEvents)
	value, raw, err := powershell(ctx, script)
	if err != nil {
		return []map[string]any{}, nil, nil, nil, false, err
	}
	return normalizeWindowsEvents(value), []model.Evidence{{Name: "evidence/errors-eventlog.json", Content: []byte(limit(raw, 8<<20))}}, nil, nil, false, nil
}

func windowsSoftware(ctx context.Context) (any, []model.Evidence, []string, []string, bool, error) {
	value, raw, err := powershell(ctx, "$paths='HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object DisplayName | Select-Object @{n='name';e={$_.DisplayName}},@{n='version';e={$_.DisplayVersion}},Publisher,InstallDate | ConvertTo-Json -Depth 4 -Compress")
	if err != nil {
		return []map[string]any{}, nil, nil, nil, false, err
	}
	var items []map[string]any
	if data, ok := value.([]any); ok {
		for _, item := range data {
			if m, ok := item.(map[string]any); ok {
				items = append(items, m)
			}
		}
	} else if item, ok := value.(map[string]any); ok {
		items = append(items, item)
	}
	return items, []model.Evidence{{Name: "evidence/software-registry.json", Content: []byte(limit(raw, 8<<20))}}, nil, nil, false, nil
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
			severity := strings.ToLower(fmt.Sprint(m["LevelDisplayName"]))
			if severity == "error" {
				severity = "error"
			} else {
				severity = "critical"
			}
			items = append(items, map[string]any{"timestamp": m["timestamp"], "severity": severity, "source": m["ProviderName"], "native_code": m["Id"], "message": m["Message"]})
		}
	}
	return items
}

func limit(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "\n[truncated]\n"
}
