package hako

import (
	"testing"

	"github.com/TokenPLS/Hako/component/dialer"
	"github.com/TokenPLS/Hako/component/pause"
)

func TestThePublishedPathSaysWhetherItIsCellular(t *testing.T) {
	orig, previousIndex, previousCellular := dialer.DefaultInterface.Load(), publishedInterfaceIndex.Load(), publishedPathCellular.Load()
	oldFlush, oldReset, oldClose, oldSessions, oldClear, oldWitness, oldRead :=
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, resetOutboundSessions, clearResolverCache, witnessPathChanged, readPhysicalResolvers
	flushInterfaceCache, resetResolverConnection, closeTrackedConnections, resetOutboundSessions, clearResolverCache = func() {}, func() {}, func() {}, func() {}, func() {}
	witnessPathChanged = func(int32) {}
	readPhysicalResolvers = func(int32) []string { return nil }
	t.Cleanup(func() {
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, resetOutboundSessions, clearResolverCache, witnessPathChanged, readPhysicalResolvers =
			oldFlush, oldReset, oldClose, oldSessions, oldClear, oldWitness, oldRead
		dialer.DefaultInterface.Store(orig)
		publishedInterfaceIndex.Store(previousIndex)
		publishedPathCellular.Store(previousCellular)
		clearBindingSuspension()
		pause.NetworkWake()
	})

	u := &interfaceUpdater{bindDefaultInterface: true}
	for _, step := range []struct {
		name     string
		index    int32
		cellular bool
	}{
		{"pdp_ip0", 2, true},
		{"en0", 18, false},
		{"pdp_ip1", 3, true},
		{"", 0, false},
	} {
		u.UpdateDefaultInterface(step.name, step.index, step.name != "en0", false, true, true)
		if got := publishedPathCellular.Load(); got != step.cellular {
			t.Fatalf("after %q the path is cellular=%v, want %v", step.name, got, step.cellular)
		}
	}
}
