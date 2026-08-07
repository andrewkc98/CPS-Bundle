//go:build !linux && !darwin && !windows

package collect

import (
	"context"
	"errors"
	"time"

	"cps-bundle/internal/model"
)

func platformCollectors(model.Options) []Collector {
	sections := []string{"identity", "hardware", "operating_system", "storage", "network", "recent_errors", "software"}
	collectors := make([]Collector, 0, len(sections))
	for _, section := range sections {
		section := section
		collectors = append(collectors, commandCollector(section, "unsupported-platform", 5*time.Second, func(context.Context) (any, []model.Evidence, []string, []string, bool, error) {
			return map[string]any{}, nil, nil, nil, false, errors.New("unsupported operating system")
		}))
	}
	return collectors
}
