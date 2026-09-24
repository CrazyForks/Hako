package hako

import (
	"path/filepath"
	"testing"

	"github.com/TokenPLS/Hako/config"
	"github.com/TokenPLS/Hako/hub/executor"
)


func armedProbeBreadcrumb(t *testing.T) string {
	t.Helper()
	home := breadcrumbHome(t)
	setStartupBreadcrumbRecording(true)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })
	t.Cleanup(armStartupProbes())
	return filepath.Join(home, breadcrumbFileName)
}

func TestApplyStepsReachTheBreadcrumbAndNotOnlyThePhaseLog(t *testing.T) {
	path := armedProbeBreadcrumb(t)

	executor.StartupProbe("profile")

	record, err := readBreadcrumb(path)
	if err != nil {
		t.Fatalf("an apply step left no breadcrumb for the next launch to read: %v", err)
	}
	if record.Stage != "apply:profile" {
		t.Fatalf("breadcrumb stage is %q, so the client's apply:profile branch is unreachable in the field", record.Stage)
	}
}

func TestParseSectionsReachTheBreadcrumbToo(t *testing.T) {
	path := armedProbeBreadcrumb(t)

	config.StartupProbe("dns")

	record, err := readBreadcrumb(path)
	if err != nil {
		t.Fatalf("a parse section left no breadcrumb: %v", err)
	}
	if record.Stage != "parse:dns" {
		t.Fatalf("breadcrumb stage is %q, so the client's parse:dns branch is unreachable in the field", record.Stage)
	}
}

func TestTheProviderBeingBuiltIsNamedBeforeItIsBuilt(t *testing.T) {
	path := armedProbeBreadcrumb(t)

	executor.StartupProbe("rule-provider-begin:reject")

	record, err := readBreadcrumb(path)
	if err != nil {
		t.Fatalf("the provider about to be built left no breadcrumb: %v", err)
	}
	if record.Resource != "rule-provider:reject" {
		t.Fatalf("breadcrumb resource is %q; a kill inside Initial would not name the provider", record.Resource)
	}
	if record.Stage != "apply:rule-provider-begin:reject" {
		t.Fatalf("breadcrumb stage is %q", record.Stage)
	}
}

func BenchmarkAnApplyStepThroughTheBreadcrumb(b *testing.B) {
	home := b.TempDir()
	previous := breadcrumbDirectory
	breadcrumbDirectory = home
	b.Cleanup(func() { breadcrumbDirectory = previous })
	setStartupBreadcrumbRecording(true)
	b.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	for i := 0; i < b.N; i++ {
		recordStartupStage("apply:profile")
	}
}

func TestDisarmingStopsTheProbesFromWritingAnything(t *testing.T) {
	home := breadcrumbHome(t)
	setStartupBreadcrumbRecording(true)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	disarm := armStartupProbes()
	disarm()

	if config.StartupProbe != nil || executor.StartupProbe != nil {
		t.Fatal("a disarmed Start left its probes installed for the next caller")
	}
	if _, err := readBreadcrumb(filepath.Join(home, breadcrumbFileName)); err == nil {
		t.Fatal("arming and disarming with no steps in between still wrote a record")
	}
}
