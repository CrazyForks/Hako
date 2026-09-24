package hako

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/component/dialer"
)

func init() {
	afterPathSettles = func(_ time.Duration, settle func()) func() bool {
		settle()
		return func() bool { return false }
	}
}

func TestABurstOfPathCallbacksIsResetOnceWhenThePathSettles(t *testing.T) {
	orig := dialer.DefaultInterface.Load()
	previousIndex := publishedInterfaceIndex.Load()
	oldSettle := afterPathSettles
	afterPathSettles = func(d time.Duration, settle func()) func() bool { return time.AfterFunc(d, settle).Stop }
	var closes, sessions, resolvers atomic.Int32
	var settledOn atomic.Int32
	oldFlush, oldReset, oldClose, oldSessions, oldClear, oldWitness :=
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, resetOutboundSessions, clearResolverCache, witnessPathChanged
	flushInterfaceCache, clearResolverCache = func() {}, func() {}
	resetResolverConnection = func() { resolvers.Add(1) }
	closeTrackedConnections = func() { closes.Add(1) }
	resetOutboundSessions = func() { sessions.Add(1) }
	witnessPathChanged = func(index int32) { settledOn.Store(index) }
	previousRead := readPhysicalResolvers
	readPhysicalResolvers = func(int32) []string { return nil }
	t.Cleanup(func() {
		dialer.DefaultInterface.Store(orig)
		publishedInterfaceIndex.Store(previousIndex)
		afterPathSettles = oldSettle
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, resetOutboundSessions, clearResolverCache, witnessPathChanged =
			oldFlush, oldReset, oldClose, oldSessions, oldClear, oldWitness
		readPhysicalResolvers = previousRead
	})

	u := &interfaceUpdater{bindDefaultInterface: true}
	u.UpdateDefaultInterface("pdp_ip0", 2, true, false, true, true)
	time.Sleep(pathSettleDelay + 100*time.Millisecond)
	if resolvers.Load() != 1 {
		t.Fatalf("the first path reset the resolver %d times, want once", resolvers.Load())
	}
	closes.Store(0)
	sessions.Store(0)
	resolvers.Store(0)

	u.UpdateDefaultInterface("pdp_ip0", 2, true, false, false, true)
	u.UpdateDefaultInterface("", 0, true, false, true, true)
	if publishedInterfaceIndex.Load() != 0 {
		t.Fatal("the index a dial binds to must be published at once, not after the settle")
	}
	u.UpdateDefaultInterface("", 0, false, false, true, false)
	u.UpdateDefaultInterface("pdp_ip0", 2, true, false, true, true)
	if closes.Load() != 0 || sessions.Load() != 0 {
		t.Fatalf("reset inside the burst: closes=%d sessions=%d", closes.Load(), sessions.Load())
	}
	time.Sleep(pathSettleDelay + 150*time.Millisecond)
	if closes.Load() != 1 || sessions.Load() != 1 || resolvers.Load() != 1 {
		t.Fatalf("closes=%d sessions=%d resolvers=%d after the burst settled, want one of each", closes.Load(), sessions.Load(), resolvers.Load())
	}
	if settledOn.Load() != 2 {
		t.Fatalf("the witness was told the path settled on index %d, want 2", settledOn.Load())
	}
}

func TestAPendingResetIsDroppedWhenTheMonitorStops(t *testing.T) {
	oldSettle := afterPathSettles
	var armed func()
	afterPathSettles = func(_ time.Duration, settle func()) func() bool {
		armed = settle
		return func() bool { return true }
	}
	var closes atomic.Int32
	oldFlush, oldReset, oldClose, oldSessions, oldClear, oldWitness :=
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, resetOutboundSessions, clearResolverCache, witnessPathChanged
	flushInterfaceCache, clearResolverCache, resetResolverConnection, resetOutboundSessions = func() {}, func() {}, func() {}, func() {}
	closeTrackedConnections = func() { closes.Add(1) }
	witnessPathChanged = func(int32) {}
	previousRead := readPhysicalResolvers
	readPhysicalResolvers = func(int32) []string { return nil }
	t.Cleanup(func() {
		afterPathSettles = oldSettle
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, resetOutboundSessions, clearResolverCache, witnessPathChanged =
			oldFlush, oldReset, oldClose, oldSessions, oldClear, oldWitness
		readPhysicalResolvers = previousRead
	})
	u := &interfaceUpdater{bindDefaultInterface: true}
	u.UpdateDefaultInterface("en0", 4, false, false, true, true)
	armed()
	u.UpdateDefaultInterface("pdp_ip0", 2, true, false, true, true)
	u.stopSettling()
	armed()
	if closes.Load() != 0 {
		t.Fatalf("a reset ran after the monitor stopped: %d", closes.Load())
	}
}
