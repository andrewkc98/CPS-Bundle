package model

import (
	"net"
	"strings"
	"time"
)

const SchemaVersion = "1.0.0"

type Options struct {
	Output       string
	Since        time.Duration
	Yes          bool
	Redact       bool
	Include      []string
	Exclude      []string
	NoEnrichers  bool
	MaxEvents    int
	CollectorVer string
}

type Bundle struct {
	Metadata        Metadata         `json:"metadata"`
	Identity        map[string]any   `json:"identity"`
	Hardware        map[string]any   `json:"hardware"`
	OperatingSystem map[string]any   `json:"operating_system"`
	Storage         map[string]any   `json:"storage"`
	Network         map[string]any   `json:"network"`
	RecentErrors    []map[string]any `json:"recent_errors"`
	Software        []map[string]any `json:"software"`
	Findings        []Finding        `json:"findings"`
	Collection      Collection       `json:"collection"`
}

type Metadata struct {
	SchemaVersion    string `json:"schema_version"`
	CollectorVersion string `json:"collector_version"`
	BundleID         string `json:"bundle_id"`
	CreatedAt        string `json:"created_at"`
	Lookback         string `json:"lookback"`
	Profile          string `json:"profile"`
	Privilege        string `json:"privilege"`
	Consent          bool   `json:"consent"`
	Redacted         bool   `json:"redacted"`
	Timezone         string `json:"timezone"`
	DurationMS       int64  `json:"duration_ms"`
}

type Collection struct {
	Status            string                   `json:"status"`
	Sections          map[string]SectionStatus `json:"sections"`
	Warnings          []string                 `json:"warnings"`
	EvidenceTruncated bool                     `json:"evidence_truncated"`
}

type SectionStatus struct {
	Status       string   `json:"status"`
	DurationMS   int64    `json:"duration_ms"`
	Source       string   `json:"source,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
	Error        string   `json:"error,omitempty"`
	MissingTools []string `json:"missing_tools,omitempty"`
	Truncated    bool     `json:"truncated,omitempty"`
}

type Finding struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Action   string `json:"suggested_action"`
	Evidence string `json:"evidence,omitempty"`
}

type Evidence struct {
	Name    string
	Content []byte
}

type Result struct {
	Section      string
	Status       string
	Source       string
	Data         any
	Evidence     []Evidence
	Warnings     []string
	MissingTools []string
	Error        string
	DurationMS   int64
	Truncated    bool
}

func NewBundle(opts Options, now time.Time) Bundle {
	zone, _ := now.Zone()
	return Bundle{
		Metadata: Metadata{
			SchemaVersion: SchemaVersion, CollectorVersion: opts.CollectorVer,
			BundleID: newID(now), CreatedAt: now.UTC().Format(time.RFC3339),
			Lookback: opts.Since.String(), Profile: "balanced", Privilege: "elevated",
			Consent: true, Redacted: opts.Redact, Timezone: zone,
		},
		Identity: map[string]any{}, Hardware: map[string]any{}, OperatingSystem: map[string]any{},
		Storage: map[string]any{}, Network: map[string]any{}, RecentErrors: []map[string]any{},
		Software: []map[string]any{}, Findings: []Finding{},
		Collection: Collection{Status: "ok", Sections: map[string]SectionStatus{}, Warnings: []string{}},
	}
}

func newID(now time.Time) string { return now.UTC().Format("20060102T150405.000000000Z") }

func Redact(b *Bundle) {
	var walk func(any) any
	walk = func(value any) any {
		switch v := value.(type) {
		case map[string]any:
			for key, item := range v {
				lower := strings.ToLower(key)
				if sensitiveField(lower) {
					v[key] = redactedValue(item)
				} else {
					v[key] = walk(item)
				}
			}
		case []any:
			for i := range v {
				v[i] = walk(v[i])
			}
		case []map[string]any:
			for i := range v {
				walk(v[i])
			}
		case []string:
			for i := range v {
				if isNetworkIdentifier(v[i]) {
					v[i] = "[REDACTED]"
				}
			}
		case string:
			if isNetworkIdentifier(v) {
				return "[REDACTED]"
			}
		}
		return value
	}
	walk(b.Identity)
	walk(b.Hardware)
	walk(b.OperatingSystem)
	walk(b.Storage)
	walk(b.Network)
	for i := range b.RecentErrors {
		walk(b.RecentErrors[i])
	}
	for i := range b.Software {
		walk(b.Software[i])
	}
	for name, status := range b.Collection.Sections {
		if status.Error != "" {
			status.Error = "[REDACTED]"
			b.Collection.Sections[name] = status
		}
	}
	b.Metadata.Redacted = true
}

func sensitiveField(key string) bool {
	return strings.Contains(key, "serial") || strings.Contains(key, "hostname") ||
		strings.Contains(key, "username") || strings.Contains(key, "ssid") ||
		strings.Contains(key, "mac") || strings.Contains(key, "public_ip") ||
		strings.Contains(key, "ip_address") || key == "ip" || key == "address" ||
		key == "raw" || key == "message" || key == "last_updates"
}

func redactedValue(value any) any {
	switch value.(type) {
	case []string:
		return []string{"[REDACTED]"}
	case []any:
		return []any{"[REDACTED]"}
	default:
		return "[REDACTED]"
	}
}

func isNetworkIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	if net.ParseIP(strings.Trim(value, "[]")) != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(value); err == nil {
		return true
	}
	return false
}
