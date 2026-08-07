package summary

import (
	"strings"
	"testing"
	"time"

	"cps-bundle/internal/model"
)

func TestRenderHTMLIsOfflineAndEscaped(t *testing.T) {
	b := model.NewBundle(model.Options{Since: time.Hour, CollectorVer: "test"}, time.Unix(0, 0))
	b.Identity["hostname"] = "<host>"
	b.Findings = []model.Finding{{Severity: "critical", Title: "Disk", Detail: "Full", Action: "Free space"}}
	text := string(RenderHTML(b))
	if strings.Contains(text, "<host>") || !strings.Contains(text, "CPS Bundle support summary") {
		t.Fatal("summary was not rendered safely")
	}
}
