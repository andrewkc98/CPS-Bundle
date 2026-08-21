package collect

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cps-bundle/internal/model"
)

type Collector struct {
	Section string
	Source  string
	Timeout time.Duration
	Run     func(context.Context) (any, []model.Evidence, []string, []string, bool, error)
}

func Confirm(opts model.Options) error {
	if opts.Yes {
		fmt.Println("CPS Bundle collecting the requested support categories with sensitive identifiers enabled (use --redact to mask common identifiers).")
		return nil
	}
	if info, err := os.Stdin.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return errors.New("confirmation required; rerun with --yes for non-interactive use")
	}
	fmt.Println("CPS Bundle will collect hardware, OS/patch, disk, network, recent errors, and installed software.")
	fmt.Println("This may include hostnames, usernames, serials, MAC/IP addresses, SSIDs, and event messages.")
	fmt.Print("Continue? [y/N] ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return errors.New("unable to read confirmation")
	}
	if strings.ToLower(strings.TrimSpace(line)) != "y" && strings.ToLower(strings.TrimSpace(line)) != "yes" {
		return errors.New("collection cancelled")
	}
	return nil
}

func Run(opts model.Options) (model.Bundle, []model.Result, error) {
	started := time.Now()
	b := model.NewBundle(opts, started)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	collectors := platformCollectors(opts)
	if err := validateSelections(collectors, opts); err != nil {
		return b, nil, err
	}
	var wg sync.WaitGroup
	results := make(chan model.Result, len(collectors))
	for _, collector := range collectors {
		collector := collector
		if !selected(collector.Section, opts) {
			b.Collection.Sections[collector.Section] = model.SectionStatus{Status: "skipped", Source: "filter"}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- runCollector(ctx, collector)
		}()
	}
	wg.Wait()
	close(results)
	var ordered []model.Result
	for result := range results {
		ordered = append(ordered, result)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Section < ordered[j].Section })
	for _, result := range ordered {
		applyResult(&b, result)
	}
	b.Metadata.DurationMS = time.Since(started).Milliseconds()
	if len(ordered) == 0 {
		return b, nil, errors.New("no collectors selected")
	}
	if b.Collection.Status == "ok" && hasIncompleteSections(b.Collection.Sections) {
		b.Collection.Status = "partial"
	}
	b.Findings = findings(b)
	return b, ordered, nil
}

func hasIncompleteSections(sections map[string]model.SectionStatus) bool {
	for _, status := range sections {
		if status.Status != "ok" && status.Status != "skipped" {
			return true
		}
	}
	return false
}

// ValidateOptions rejects category names that do not exist on the current platform.
func ValidateOptions(opts model.Options) error {
	return validateSelections(platformCollectors(opts), opts)
}

func validateSelections(collectors []Collector, opts model.Options) error {
	known := make(map[string]bool, len(collectors))
	for _, collector := range collectors {
		known[collector.Section] = true
	}
	for _, filter := range []struct {
		name   string
		values []string
	}{{"--include", opts.Include}, {"--exclude", opts.Exclude}} {
		for _, section := range filter.values {
			if !known[section] {
				return fmt.Errorf("%s contains unknown category %q (valid categories: %s)", filter.name, section, strings.Join(knownSections(known), ", "))
			}
		}
	}
	return nil
}

func knownSections(known map[string]bool) []string {
	sections := make([]string, 0, len(known))
	for section := range known {
		sections = append(sections, section)
	}
	sort.Strings(sections)
	return sections
}

func runCollector(ctx context.Context, collector Collector) (result model.Result) {
	started := time.Now()
	result = model.Result{Section: collector.Section, Source: collector.Source, Status: "failed"}
	defer func() {
		if recovered := recover(); recovered != nil {
			result.Status = "failed"
			result.Error = fmt.Sprintf("collector panic: %v", recovered)
			result.Data = nil
			result.Evidence = nil
			result.Warnings = nil
			result.MissingTools = nil
			result.Truncated = false
		}
		result.DurationMS = time.Since(started).Milliseconds()
	}()
	localCtx, stop := context.WithTimeout(ctx, collector.Timeout)
	defer stop()
	data, evidence, warnings, missing, truncated, err := collector.Run(localCtx)
	result.Data, result.Evidence = data, evidence
	result.Warnings, result.MissingTools, result.Truncated = warnings, missing, truncated
	result.Status = "ok"
	if err != nil {
		result.Status = "failed"
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(localCtx.Err(), context.DeadlineExceeded) {
			result.Status = "unavailable"
		}
	}
	if (len(warnings) > 0 || len(missing) > 0 || truncated) && result.Status == "ok" {
		result.Status = "partial"
	}
	result.Error = errorText(err)
	return result
}

func selected(section string, opts model.Options) bool {
	for _, item := range opts.Exclude {
		if item == section {
			return false
		}
	}
	if len(opts.Include) == 0 {
		return true
	}
	for _, item := range opts.Include {
		if item == section {
			return true
		}
	}
	return false
}

func applyResult(b *model.Bundle, result model.Result) {
	b.Collection.Sections[result.Section] = model.SectionStatus{Status: result.Status, Source: result.Source, DurationMS: result.DurationMS, Warnings: result.Warnings, MissingTools: result.MissingTools, Error: result.Error, Truncated: result.Truncated}
	if result.Status != "ok" {
		b.Collection.Warnings = append(b.Collection.Warnings, result.Section+": "+result.Status)
	}
	if result.Truncated {
		b.Collection.EvidenceTruncated = true
	}
	switch result.Section {
	case "identity":
		if value, ok := result.Data.(map[string]any); ok {
			b.Identity = value
		}
	case "hardware":
		if value, ok := result.Data.(map[string]any); ok {
			b.Hardware = value
		}
	case "operating_system":
		if value, ok := result.Data.(map[string]any); ok {
			b.OperatingSystem = value
		}
	case "storage":
		if value, ok := result.Data.(map[string]any); ok {
			b.Storage = value
		}
	case "network":
		if value, ok := result.Data.(map[string]any); ok {
			b.Network = value
		}
	case "recent_errors":
		if value, ok := result.Data.([]map[string]any); ok {
			b.RecentErrors = groupErrors(value)
		}
	case "software":
		if value, ok := result.Data.([]map[string]any); ok {
			b.Software = value
		}
	}
}

func groupErrors(events []map[string]any) []map[string]any {
	grouped := make([]map[string]any, 0, len(events))
	positions := map[string]int{}
	for _, event := range events {
		key := fmt.Sprintf("%v|%v|%v|%v", event["severity"], event["source"], event["native_code"], event["message"])
		if position, ok := positions[key]; ok {
			count, _ := grouped[position]["occurrence_count"].(int)
			grouped[position]["occurrence_count"] = count + 1
			if compareTimestamp(event["timestamp"], grouped[position]["first_occurrence"]) < 0 {
				grouped[position]["first_occurrence"] = event["timestamp"]
			}
			if compareTimestamp(event["timestamp"], grouped[position]["last_occurrence"]) > 0 {
				grouped[position]["last_occurrence"] = event["timestamp"]
			}
			continue
		}
		copy := map[string]any{}
		for name, value := range event {
			copy[name] = value
		}
		copy["first_occurrence"] = event["timestamp"]
		copy["last_occurrence"] = event["timestamp"]
		copy["occurrence_count"] = 1
		positions[key] = len(grouped)
		grouped = append(grouped, copy)
	}
	return grouped
}

func compareTimestamp(left, right any) int {
	leftTime, leftOK := parseTimestamp(left)
	rightTime, rightOK := parseTimestamp(right)
	if leftOK && rightOK {
		if leftTime.Before(rightTime) {
			return -1
		}
		if leftTime.After(rightTime) {
			return 1
		}
		return 0
	}
	leftText, rightText := fmt.Sprint(left), fmt.Sprint(right)
	if leftText < rightText {
		return -1
	}
	if leftText > rightText {
		return 1
	}
	return 0
}

func parseTimestamp(value any) (time.Time, bool) {
	text := strings.TrimSpace(fmt.Sprint(value))
	if text == "" || text == "<nil>" {
		return time.Time{}, false
	}
	if strings.HasPrefix(text, "/Date(") && strings.HasSuffix(text, ")/") {
		milliseconds, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(text, "/Date("), ")/"), 10, 64)
		if err == nil {
			return time.UnixMilli(milliseconds), true
		}
	}
	if parsed, err := time.Parse(time.RFC3339Nano, text); err == nil {
		return parsed, true
	}
	if numeric, err := strconv.ParseInt(text, 10, 64); err == nil {
		if numeric > 1_000_000_000_000 {
			return time.UnixMicro(numeric), true
		}
		return time.Unix(numeric, 0), true
	}
	return time.Time{}, false
}

func findings(b model.Bundle) []model.Finding {
	findings := make([]model.Finding, 0, 10)
	sections := make([]string, 0, len(b.Collection.Sections))
	for section := range b.Collection.Sections {
		sections = append(sections, section)
	}
	sort.Strings(sections)
	for _, section := range sections {
		status := b.Collection.Sections[section]
		if status.Status == "failed" || status.Status == "unavailable" {
			findings = append(findings, model.Finding{Severity: "warning", Title: section + " collection incomplete", Detail: status.Error, Action: "Review the collection warning and rerun with the required OS privileges or tools."})
		}
	}
	if reboot, ok := b.OperatingSystem["reboot_pending"].(bool); ok && reboot {
		findings = append(findings, model.Finding{Severity: "warning", Title: "Reboot pending", Detail: "The operating system reports that a restart is required.", Action: "Restart the device during an approved maintenance window."})
	}
	if value, ok := b.Storage["volumes"].([]any); ok {
		for _, item := range value {
			if volume, ok := item.(map[string]any); ok {
				if used, ok := volume["used_percent"].(float64); ok && used >= 95 {
					findings = append(findings, model.Finding{Severity: "critical", Title: "Storage critically full", Detail: fmt.Sprintf("A volume is %.1f%% used.", used), Action: "Free space or extend the affected volume."})
				} else if ok && used >= 85 {
					findings = append(findings, model.Finding{Severity: "warning", Title: "Storage capacity pressure", Detail: fmt.Sprintf("A volume is %.1f%% used.", used), Action: "Review large files and plan capacity remediation."})
				}
			}
		}
	}
	for _, event := range b.RecentErrors {
		severity, _ := event["severity"].(string)
		if severity == "critical" {
			findings = append(findings, model.Finding{Severity: "critical", Title: "Recent critical system errors", Detail: "One or more critical events were observed in the lookback window.", Action: "Review recent_errors and the corresponding evidence excerpt."})
			break
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		return findingSeverityRank(findings[i].Severity) < findingSeverityRank(findings[j].Severity)
	})
	if len(findings) > 10 {
		findings = findings[:10]
	}
	return findings
}

func findingSeverityRank(severity string) int {
	switch severity {
	case "critical":
		return 0
	case "warning":
		return 1
	default:
		return 2
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

func runText(ctx context.Context, name string, args ...string) (string, error) {
	data, err := runCommand(ctx, name, args...)
	return string(data), err
}

func runJSON(ctx context.Context, name string, args ...string) (any, string, error) {
	text, err := runText(ctx, name, args...)
	if err != nil {
		return nil, text, err
	}
	var value any
	if err := json.Unmarshal([]byte(text), &value); err != nil {
		return nil, text, err
	}
	return value, text, nil
}

func lookupCommand(name string) (string, error) { return exec.LookPath(name) }

// limit caps collected text and makes the truncation explicit in the evidence.
func limit(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "\n[truncated]\n"
}

func commandCollector(section, source string, timeout time.Duration, fn func(context.Context) (any, []model.Evidence, []string, []string, bool, error)) Collector {
	return Collector{Section: section, Source: source, Timeout: timeout, Run: fn}
}
