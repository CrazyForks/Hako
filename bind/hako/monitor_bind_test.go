package hako

import (
	"sync/atomic"
	"testing"

	"github.com/TokenPLS/Hako/component/dialer"
	"github.com/TokenPLS/Hako/component/pause"
)

func TestInterfaceUpdaterUpdatesDialer(t *testing.T) {
	orig := dialer.DefaultInterface.Load()
	t.Cleanup(func() { dialer.DefaultInterface.Store(orig) })

	var flushes, resets, closes atomic.Int32
	oldFlush, oldReset := flushInterfaceCache, resetResolverConnection
	oldClose := closeTrackedConnections
	flushInterfaceCache = func() { flushes.Add(1) }
	resetResolverConnection = func() { resets.Add(1) }
	closeTrackedConnections = func() { closes.Add(1) }
	t.Cleanup(func() {
		flushInterfaceCache, resetResolverConnection = oldFlush, oldReset
		closeTrackedConnections = oldClose
	})

	u := &interfaceUpdater{bindDefaultInterface: true}
	u.UpdateDefaultInterface("en0", 4, false, false, true, true)
	if got := dialer.DefaultInterface.Load(); got != "en0" {
		t.Fatalf("DefaultInterface = %q, want en0", got)
	}
	u.UpdateDefaultInterface("en0", 4, false, false, true, true)
	if flushes.Load() != 1 || resets.Load() != 1 {
		t.Fatalf("identical path thrashed caches: flush=%d reset=%d", flushes.Load(), resets.Load())
	}
	if closes.Load() != 0 {
		t.Fatalf("initial path closed connections: %d", closes.Load())
	}
	u.UpdateDefaultInterface("en0", 4, false, true, true, true)
	if flushes.Load() != 2 || resets.Load() != 2 {
		t.Fatalf("same-interface capability change was ignored: flush=%d reset=%d", flushes.Load(), resets.Load())
	}
	if closes.Load() != 0 {
		t.Fatalf("capability-only change closed connections: %d", closes.Load())
	}
	u.UpdateDefaultInterface("en0", 4, false, true, false, true)
	if closes.Load() != 1 || flushes.Load() != 3 || resets.Load() != 3 {
		t.Fatalf("address-family transition close/flush/reset=%d/%d/%d", closes.Load(), flushes.Load(), resets.Load())
	}
	u.UpdateDefaultInterface("pdp_ip0", 10, true, false, true, true)
	if got := dialer.DefaultInterface.Load(); got != "pdp_ip0" {
		t.Fatalf("DefaultInterface = %q, want pdp_ip0", got)
	}
	if flushes.Load() != 4 || resets.Load() != 4 {
		t.Fatalf("interface switch did not reset state: flush=%d reset=%d", flushes.Load(), resets.Load())
	}
	if closes.Load() != 2 {
		t.Fatalf("interface switch closed %d connection sets, want 2", closes.Load())
	}

	u.UpdateDefaultInterface("", 0, false, false, false, false)
	if got := dialer.DefaultInterface.Load(); got != "" {
		t.Fatalf("unavailable path left DefaultInterface=%q", got)
	}
	if closes.Load() != 3 || flushes.Load() != 5 || resets.Load() != 5 {
		t.Fatalf("path loss cleanup close/flush/reset=%d/%d/%d", closes.Load(), flushes.Load(), resets.Load())
	}

	snapshot := u.snapshot()
	if snapshot.received != 6 || snapshot.applied != 5 {
		t.Fatalf("path update telemetry received/applied=%d/%d, want 6/5", snapshot.received, snapshot.applied)
	}
	if snapshot.identityChanges != 2 || snapshot.connectionResets != 3 {
		t.Fatalf("path handover telemetry identity/reset=%d/%d, want 2/3", snapshot.identityChanges, snapshot.connectionResets)
	}
}

func TestInterfaceUpdaterTreatsSameNameIndexChangeAsIdentityChange(t *testing.T) {
	orig := dialer.DefaultInterface.Load()
	t.Cleanup(func() { dialer.DefaultInterface.Store(orig) })

	var flushes, resets, closes atomic.Int32
	oldFlush, oldReset := flushInterfaceCache, resetResolverConnection
	oldClose := closeTrackedConnections
	flushInterfaceCache = func() { flushes.Add(1) }
	resetResolverConnection = func() { resets.Add(1) }
	closeTrackedConnections = func() { closes.Add(1) }
	t.Cleanup(func() {
		flushInterfaceCache, resetResolverConnection = oldFlush, oldReset
		closeTrackedConnections = oldClose
	})

	u := &interfaceUpdater{bindDefaultInterface: true}
	u.UpdateDefaultInterface("en0", 4, false, false, true, true)
	u.UpdateDefaultInterface("en0", 5, false, false, true, true)

	snapshot := u.snapshot()
	if flushes.Load() != 2 || resets.Load() != 2 || closes.Load() != 1 {
		t.Fatalf("same-name index change close/flush/reset=%d/%d/%d, want 1/2/2",
			closes.Load(), flushes.Load(), resets.Load())
	}
	if snapshot.identityChanges != 1 || snapshot.connectionResets != 1 {
		t.Fatalf("same-name index telemetry identity/reset=%d/%d, want 1/1",
			snapshot.identityChanges, snapshot.connectionResets)
	}
}

func TestStartInterfaceMonitorOptOut(t *testing.T) {
	setupRuntimeProfile.Store(uint32(runtimeProfileIOSPacketTunnel))
	listener, err := startInterfaceMonitor(&recordingPlatform{})
	if err != nil || listener != nil {
		t.Fatalf("opt-out should return (nil, nil), got (%v, %v)", listener, err)
	}
}

func TestMacOSPacketTunnelMonitorsPathWithoutSocketBinding(t *testing.T) {
	originalProfile := currentRuntimeProfile()
	setupRuntimeProfile.Store(uint32(runtimeProfileMacOSPacketTunnel))
	t.Cleanup(func() { setupRuntimeProfile.Store(uint32(originalProfile)) })

	platform := &recordingPlatform{}
	listener, err := startInterfaceMonitor(platform)
	if err != nil {
		t.Fatalf("startInterfaceMonitor: %v", err)
	}
	if listener == nil || platform.monitorStarts != 1 {
		t.Fatalf("macOS Packet Tunnel monitor listener/starts = %v/%d, want non-nil/1",
			listener, platform.monitorStarts)
	}
	updater, ok := listener.(*interfaceUpdater)
	if !ok {
		t.Fatalf("listener type = %T, want *interfaceUpdater", listener)
	}
	if updater.bindDefaultInterface {
		t.Fatal("macOS NECP path monitor must not force dialer.DefaultInterface")
	}
}

func TestInterfaceUpdaterCanRefreshStateWithoutForcingDefaultInterface(t *testing.T) {
	originalInterface := dialer.DefaultInterface.Load()
	dialer.DefaultInterface.Store("necp-provider-default")
	t.Cleanup(func() { dialer.DefaultInterface.Store(originalInterface) })

	var flushes, resets, closes atomic.Int32
	oldFlush, oldReset := flushInterfaceCache, resetResolverConnection
	oldClose := closeTrackedConnections
	flushInterfaceCache = func() { flushes.Add(1) }
	resetResolverConnection = func() { resets.Add(1) }
	closeTrackedConnections = func() { closes.Add(1) }
	t.Cleanup(func() {
		flushInterfaceCache, resetResolverConnection = oldFlush, oldReset
		closeTrackedConnections = oldClose
	})

	updater := &interfaceUpdater{bindDefaultInterface: false}
	updater.UpdateDefaultInterface("en0", 4, false, false, true, true)
	updater.UpdateDefaultInterface("en1", 5, false, false, true, true)

	if got := dialer.DefaultInterface.Load(); got != "necp-provider-default" {
		t.Fatalf("unbound updater changed DefaultInterface = %q", got)
	}
	if flushes.Load() != 2 || resets.Load() != 2 || closes.Load() != 1 {
		t.Fatalf("unbound updater close/flush/reset = %d/%d/%d, want 1/2/2",
			closes.Load(), flushes.Load(), resets.Load())
	}
}

func TestNoDefaultNetworkSuspendsPeriodicWork(t *testing.T) {
	oldFlush, oldReset, oldClose, oldClear :=
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, clearResolverCache
	flushInterfaceCache = func() {}
	resetResolverConnection = func() {}
	closeTrackedConnections = func() {}
	clearResolverCache = func() {}
	previousRead := readPhysicalResolvers
	readPhysicalResolvers = func(int32) []string { return nil }
	t.Cleanup(func() {
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, clearResolverCache =
			oldFlush, oldReset, oldClose, oldClear
		readPhysicalResolvers = previousRead
		pause.NetworkWake()
	})

	pause.NetworkWake()
	updater := &interfaceUpdater{bindDefaultInterface: true}
	updater.UpdateDefaultInterface("en0", 5, false, false, true, true)
	if pause.IsNetworkPaused() {
		t.Fatal("a usable default network must not suspend anything")
	}

	updater.UpdateDefaultInterface("", 0, false, false, false, false)
	if !pause.IsNetworkPaused() {
		t.Fatal("no usable default network must suspend the periodic work")
	}

	updater.UpdateDefaultInterface("pdp_ip0", 7, true, false, true, false)
	if pause.IsNetworkPaused() {
		t.Fatal("a network returning must resume the periodic work")
	}
	if networkPauseStarted.Load().IsZero() {
		t.Fatal("the window's start must be recorded so the closing line can report its length")
	}
}

func TestNetworkPauseWindowIsStampedOnceAtItsStart(t *testing.T) {
	oldFlush, oldReset, oldClose, oldClear :=
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, clearResolverCache
	flushInterfaceCache = func() {}
	resetResolverConnection = func() {}
	closeTrackedConnections = func() {}
	clearResolverCache = func() {}
	previousRead := readPhysicalResolvers
	readPhysicalResolvers = func(int32) []string { return nil }
	t.Cleanup(func() {
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, clearResolverCache =
			oldFlush, oldReset, oldClose, oldClear
		readPhysicalResolvers = previousRead
		pause.NetworkWake()
	})
	pause.NetworkWake()

	updater := &interfaceUpdater{bindDefaultInterface: true}
	updater.UpdateDefaultInterface("en0", 5, false, false, true, true)
	updater.UpdateDefaultInterface("", 0, false, false, false, false)
	opened := networkPauseStarted.Load()
	if opened.IsZero() {
		t.Fatal("opening the window must stamp its start")
	}
	updater.UpdateDefaultInterface("", 0, true, false, false, false)
	if got := networkPauseStarted.Load(); !got.Equal(opened) {
		t.Fatalf("the stamp moved inside one window: %v -> %v", opened, got)
	}
}

func TestClosingReleasesANetworkPause(t *testing.T) {
	t.Cleanup(func() { pause.NetworkWake() })
	pause.NetworkPause()
	if !pause.IsNetworkPaused() {
		t.Fatal("precondition: the network pause must be in force")
	}
	pause.NetworkWake()
	if pause.IsNetworkPaused() {
		t.Fatal("closing must release a network pause this service put in force")
	}
}

func TestANewDefaultInterfaceResetsTheOutboundsSessions(t *testing.T) {
	orig := dialer.DefaultInterface.Load()
	t.Cleanup(func() { dialer.DefaultInterface.Store(orig) })
	var sessionResets atomic.Int32
	oldFlush, oldReset, oldClose, oldSessions := flushInterfaceCache, resetResolverConnection, closeTrackedConnections, resetOutboundSessions
	flushInterfaceCache, resetResolverConnection, closeTrackedConnections = func() {}, func() {}, func() {}
	resetOutboundSessions = func() { sessionResets.Add(1) }
	t.Cleanup(func() {
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, resetOutboundSessions = oldFlush, oldReset, oldClose, oldSessions
	})
	u := &interfaceUpdater{bindDefaultInterface: true}
	u.UpdateDefaultInterface("en0", 4, false, false, true, true)
	u.UpdateDefaultInterface("en0", 4, true, false, true, true)
	if got := sessionResets.Load(); got != 0 {
		t.Fatalf("the first path and a flag flip reset %d sessions, want none", got)
	}
	u.UpdateDefaultInterface("pdp_ip0", 2, true, false, true, true)
	if got := sessionResets.Load(); got != 1 {
		t.Fatalf("a new default interface reset sessions %d times, want once", got)
	}
}
