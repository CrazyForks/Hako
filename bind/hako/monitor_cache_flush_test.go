package hako

import (
	"sync/atomic"
	"testing"
)


func TestDNSCacheFlushTracksTheResolverReset(t *testing.T) {
	oldFlush, oldReset, oldClose, oldClear :=
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, clearResolverCache
	var flushes, resets, closes, clears atomic.Int64
	flushInterfaceCache = func() { flushes.Add(1) }
	resetResolverConnection = func() { resets.Add(1) }
	closeTrackedConnections = func() { closes.Add(1) }
	clearResolverCache = func() { clears.Add(1) }
	t.Cleanup(func() {
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, clearResolverCache =
			oldFlush, oldReset, oldClose, oldClear
	})

	updater := &interfaceUpdater{}

	updater.UpdateDefaultInterface("en0", 4, false, false, true, true)
	if clears.Load() != 1 {
		t.Fatalf("first path did not flush the DNS cache: clears=%d", clears.Load())
	}

	updater.UpdateDefaultInterface("en0", 4, false, false, true, true)
	if clears.Load() != 1 {
		t.Fatalf("identical path flushed the DNS cache again: clears=%d", clears.Load())
	}

	updater.UpdateDefaultInterface("en0", 4, false, true, true, true)
	if clears.Load() != 2 {
		t.Fatalf("capability-only change did not flush the DNS cache: clears=%d", clears.Load())
	}

	updater.UpdateDefaultInterface("en0", 4, false, true, false, true)
	if clears.Load() != 3 {
		t.Fatalf("address-family transition did not flush the DNS cache: clears=%d", clears.Load())
	}

	updater.UpdateDefaultInterface("pdp_ip0", 10, true, false, true, true)
	if clears.Load() != 4 {
		t.Fatalf("interface switch did not flush the DNS cache: clears=%d", clears.Load())
	}

	if clears.Load() != resets.Load() {
		t.Fatalf("cache flush (%d) and connection reset (%d) disagree; both are invalidating "+
			"state scoped to the old path and must fire together", clears.Load(), resets.Load())
	}
}
