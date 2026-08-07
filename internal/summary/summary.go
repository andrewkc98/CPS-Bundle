package summary

import (
	"bytes"
	"fmt"
	"html"
	"sort"
	"strings"

	"cps-bundle/internal/model"
)

func RenderHTML(b model.Bundle) []byte {
	findings := append([]model.Finding(nil), b.Findings...)
	sort.SliceStable(findings, func(i, j int) bool { return severityRank(findings[i].Severity) < severityRank(findings[j].Severity) })
	var out bytes.Buffer
	out.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>CPS Bundle summary</title><style>
@page{size:auto;margin:12mm}body{font:12px/1.35 system-ui,-apple-system,Segoe UI,sans-serif;color:#1d2433;margin:0}h1{font-size:20px;margin:0 0 2px}h2{font-size:13px;border-bottom:1px solid #ccd3df;padding-bottom:3px;margin:12px 0 5px}p{margin:2px 0}.muted{color:#596579}.grid{display:grid;grid-template-columns:1fr 1fr;gap:3px 20px}.finding{padding:4px 6px;border-left:4px solid #98a2b3;margin:3px 0;background:#f5f7fa}.critical{border-color:#c0392b}.warning{border-color:#d68910}.info{border-color:#2779bd}.pill{font-size:10px;text-transform:uppercase;font-weight:700}.small{font-size:10px}footer{margin-top:12px;border-top:1px solid #ccd3df;padding-top:4px}</style></head><body>`)
	out.WriteString("<h1>CPS Bundle support summary</h1>")
	out.WriteString(fmt.Sprintf("<p class=muted>Bundle %s · created %s · schema %s</p>", esc(b.Metadata.BundleID), esc(b.Metadata.CreatedAt), esc(b.Metadata.SchemaVersion)))
	out.WriteString("<h2>Machine</h2><div class=grid>")
	writeMapFields(&out, b.Identity, []string{"hostname", "manufacturer", "model", "serial", "architecture"})
	out.WriteString("</div><h2>Operating system</h2><div class=grid>")
	writeMapFields(&out, b.OperatingSystem, []string{"name", "version", "build", "kernel", "last_update", "reboot_pending"})
	out.WriteString("</div><h2>Hardware</h2><div class=grid>")
	writeMapFields(&out, b.Hardware, []string{"cpu_model", "cpu_logical_count", "uptime_seconds"})
	if memory, ok := b.Hardware["memory_bytes"].(map[string]any); ok {
		if total, ok := memory["MemTotal"]; ok {
			out.WriteString(fmt.Sprintf("<p><strong>memory total</strong>: %s bytes</p>", esc(fmt.Sprint(total))))
		}
	} else if total, ok := b.Hardware["memory_bytes"].(float64); ok {
		out.WriteString(fmt.Sprintf("<p><strong>memory total</strong>: %.1f GB</p>", total/float64(1<<30)))
	} else if total, ok := b.Hardware["memory_bytes"].(int64); ok {
		out.WriteString(fmt.Sprintf("<p><strong>memory total</strong>: %.1f GB</p>", float64(total)/float64(1<<30)))
	}
	out.WriteString("</div><h2>Collection coverage</h2><div class=grid>")
	keys := make([]string, 0, len(b.Collection.Sections))
	for key := range b.Collection.Sections {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		status := b.Collection.Sections[key]
		out.WriteString(fmt.Sprintf("<p><strong>%s</strong>: %s</p>", esc(key), esc(status.Status)))
	}
	out.WriteString("</div><h2>Storage and network</h2><div class=grid>")
	writeMapFields(&out, b.Storage, []string{"health"})
	if volumes, ok := b.Storage["volumes"].([]any); ok {
		out.WriteString(fmt.Sprintf("<p><strong>storage volumes</strong>: %d</p>", len(volumes)))
		maxUsed := 0.0
		for _, item := range volumes {
			if volume, ok := item.(map[string]any); ok {
				if used, ok := volume["used_percent"].(float64); ok && used > maxUsed {
					maxUsed = used
				}
			}
		}
		if maxUsed > 0 {
			out.WriteString(fmt.Sprintf("<p><strong>highest volume use</strong>: %.1f%%</p>", maxUsed))
		}
	}
	out.WriteString(fmt.Sprintf("<p><strong>network interfaces</strong>: %d</p>", countItems(b.Network["interfaces"])))
	out.WriteString(fmt.Sprintf("<p><strong>DNS servers</strong>: %d</p>", countItems(b.Network["dns"])))
	out.WriteString("</div><h2>Findings</h2>")
	if len(findings) == 0 {
		out.WriteString("<p>No deterministic findings were raised.</p>")
	} else {
		for _, finding := range findings {
			out.WriteString(fmt.Sprintf("<div class=\"finding %s\"><span class=pill>%s</span> <strong>%s</strong><br>%s<br><span class=muted>Action: %s</span></div>", esc(finding.Severity), esc(finding.Severity), esc(finding.Title), esc(finding.Detail), esc(finding.Action)))
		}
	}
	out.WriteString("<h2>At a glance</h2><div class=grid>")
	out.WriteString(fmt.Sprintf("<p><strong>Recent errors</strong>: %d</p><p><strong>Installed software records</strong>: %d</p>", len(b.RecentErrors), len(b.Software)))
	out.WriteString(fmt.Sprintf("<p><strong>Profile</strong>: %s</p><p><strong>Redacted</strong>: %t</p>", esc(b.Metadata.Profile), b.Metadata.Redacted))
	out.WriteString("</div><footer class=small>Generated offline by cps-bundle. Review bundle.json and evidence/ for full detail. Native event messages may contain sensitive support context.</footer></body></html>")
	return out.Bytes()
}

func writeMapFields(out *bytes.Buffer, value map[string]any, keys []string) {
	for _, key := range keys {
		if item, ok := value[key]; ok && item != nil && fmt.Sprint(item) != "" && fmt.Sprint(item) != "<nil>" {
			out.WriteString(fmt.Sprintf("<p><strong>%s</strong>: %s</p>", esc(strings.ReplaceAll(key, "_", " ")), esc(fmt.Sprint(item))))
		}
	}
}

func countItems(value any) int {
	switch typed := value.(type) {
	case []any:
		return len(typed)
	case []map[string]any:
		return len(typed)
	case map[string]any:
		for _, key := range []string{"config", "interfaces", "dns", "routes"} {
			if child, ok := typed[key]; ok {
				return countItems(child)
			}
		}
		return len(typed)
	default:
		return 0
	}
}
func severityRank(value string) int {
	switch value {
	case "critical":
		return 0
	case "warning":
		return 1
	default:
		return 2
	}
}
func esc(value string) string { return html.EscapeString(value) }
