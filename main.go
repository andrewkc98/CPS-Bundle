package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"cps-bundle/internal/bundle"
	"cps-bundle/internal/collect"
	"cps-bundle/internal/model"
	"cps-bundle/internal/schema"
)

var version = "0.1.0"

func main() {
	command := "collect"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command, args = args[0], args[1:]
	}

	switch command {
	case "version":
		fmt.Printf("cps-bundle %s\n", version)
		return
	case "schema":
		fmt.Print(schema.Document)
		return
	case "collect":
		exitCode, err := runCollect(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cps-bundle: %v\n", err)
			os.Exit(1)
		}
		if exitCode != 0 {
			os.Exit(exitCode)
		}
	default:
		fmt.Fprintf(os.Stderr, "cps-bundle: unknown command %q (use collect, schema, or version)\n", command)
		os.Exit(2)
	}
}

func runCollect(args []string) (int, error) {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	output := fs.String("output", "", "directory or .zip destination")
	since := fs.Duration("since", 72*time.Hour, "lookback window for recent errors")
	yes := fs.Bool("yes", false, "acknowledge sensitive collection in non-interactive use")
	redact := fs.Bool("redact", false, "redact common identifiers before packaging")
	include := fs.String("include", "", "comma-separated categories to collect")
	exclude := fs.String("exclude", "", "comma-separated categories to skip")
	noEnrichers := fs.Bool("no-enrichers", false, "do not use optional installed utilities")
	maxEvents := fs.Int("max-events", 2000, "maximum normalized recent errors")
	strict := fs.Bool("strict", false, "exit 3 after writing a bundle with failed, unavailable, or partial sections")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 0, err
	}
	if *since <= 0 {
		return 0, errors.New("--since must be positive")
	}
	if *maxEvents < 1 {
		return 0, errors.New("--max-events must be positive")
	}

	if err := collect.RequirePrivilege(); err != nil {
		return 0, err
	}
	opts := model.Options{
		Output:       *output,
		Since:        *since,
		Yes:          *yes,
		Redact:       *redact,
		Include:      splitList(*include),
		Exclude:      splitList(*exclude),
		NoEnrichers:  *noEnrichers,
		MaxEvents:    *maxEvents,
		CollectorVer: version,
	}
	if err := collect.ValidateOptions(opts); err != nil {
		return 0, err
	}
	if err := collect.Confirm(opts); err != nil {
		return 0, err
	}
	doc, results, err := collect.Run(opts)
	if err != nil {
		return 0, err
	}
	if opts.Redact {
		model.Redact(&doc)
	}
	path, err := bundle.Write(opts, doc, results)
	if err != nil {
		return 0, err
	}
	fmt.Printf("Support bundle written to %s\n", path)
	if summary := nonOKSectionSummary(results); summary != "" {
		fmt.Printf("Collection completed with non-ok sections: %s\n", summary)
	}
	return strictExitCode(*strict, results), nil
}

func strictExitCode(strict bool, results []model.Result) int {
	if strict && nonOKSectionSummary(results) != "" {
		return 3
	}
	return 0
}

func nonOKSectionSummary(results []model.Result) string {
	sections := make([]string, 0)
	for _, result := range results {
		if result.Status != "ok" && result.Status != "skipped" {
			sections = append(sections, result.Section+"="+result.Status)
		}
	}
	return strings.Join(sections, ", ")
}

func splitList(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(strings.ToLower(item)); item != "" {
			out = append(out, item)
		}
	}
	return out
}
