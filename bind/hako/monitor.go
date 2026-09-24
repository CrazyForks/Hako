package hako

import (
	"strings"
	"sync"
	"time"

	"github.com/TokenPLS/Hako/common/atomic"
	"github.com/TokenPLS/Hako/component/dialer"
	"github.com/TokenPLS/Hako/component/iface"
	"github.com/TokenPLS/Hako/component/pause"
	"github.com/TokenPLS/Hako/component/resolver"
	"github.com/TokenPLS/Hako/dns"
	"github.com/TokenPLS/Hako/log"
)

type interfaceUpdater struct {
	mu                   sync.Mutex
	bindDefaultInterface bool
	initialized          bool
	name                 string
	index                int32
	initialName      string
	initialIndex     int32
	isExpensive      bool
	isConstrained    bool
	supportsIPv4     bool
	supportsIPv6     bool
	received         uint64
	applied          uint64
	identityChanges  uint64
	connectionResets uint64

	settleMu        sync.Mutex
	settleGen       uint64
	settleStop      func() bool
	pendingFlows    bool
	pendingResolver bool
	pendingWitness  bool
	pendingIndex    int32
	stopped         bool
}

type interfaceUpdateSnapshot struct {
	received         uint64
	applied          uint64
	identityChanges  uint64
	connectionResets uint64
}

var (
	flushInterfaceCache     = iface.FlushCache
	resetResolverConnection = resolver.ResetConnection
	clearResolverCache      = resolver.ClearCache
	closeTrackedConnections = CloseAllConnections
	resetOutboundSessions = func() { resetEveryOutboundSession() }
	witnessPathChanged = func(index int32) { witness.pathChanged(index) }
	afterPathSettles = func(d time.Duration, settle func()) func() bool { return time.AfterFunc(d, settle).Stop }
	readPhysicalResolvers = physicalResolversForInterface
	dnsConfigurationChanged = dnsInfoChanged
	networkPauseStarted = atomic.NewTypedValue[time.Time](time.Time{})
)

func (u *interfaceUpdater) UpdateDefaultInterface(name string, index int32, isExpensive bool, isConstrained bool, supportsIPv4 bool, supportsIPv6 bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.received++
	wasInitialized := u.initialized
	identityChanged := u.name != name || u.index != index
	addressFamiliesChanged := u.supportsIPv4 != supportsIPv4 || u.supportsIPv6 != supportsIPv6
	changed := !u.initialized || u.name != name || u.index != index ||
		u.isExpensive != isExpensive || u.isConstrained != isConstrained || addressFamiliesChanged
	if !changed {
		if u.initialized && dnsConfigurationChanged() {
			u.publishLivePhysicalResolvers()
		}
		return
	}
	u.applied++
	if !u.initialized {
		u.initialName = name
		u.initialIndex = index
	}
	u.initialized = true
	u.name = name
	u.index = index
	u.isExpensive = isExpensive
	u.isConstrained = isConstrained
	u.supportsIPv4 = supportsIPv4
	u.supportsIPv6 = supportsIPv6
	setPhysicalNetworkCapabilities(supportsIPv4, supportsIPv6)

	if u.bindDefaultInterface {
		dialer.DefaultInterface.Store(name)
	}
	publishedInterfaceIndex.Store(index)
	clearBindingSuspension()
	if index == 0 || name == "" {
		if !pause.IsNetworkPaused() {
			networkPauseStarted.Store(time.Now())
		}
		pause.NetworkPause()
		log.Warnln("[Apple] no usable default network; periodic tasks are suspended until one returns")
	} else {
		if pause.IsNetworkPaused() {
			log.Warnln("[Apple] default network is back on %s (index=%d) after %s; periodic tasks resume",
				name, index, time.Since(networkPauseStarted.Load()).Round(time.Millisecond))
		}
		pause.NetworkWake()
	}
	if wasInitialized && (identityChanged || addressFamiliesChanged) {
		if identityChanged {
			u.identityChanges++
		}
		u.connectionResets++
		u.owe(func() { u.pendingFlows = true })
	}
	if wasInitialized && identityChanged {
		u.owe(func() { u.pendingWitness = true })
	}
	flushInterfaceCache()
	invalidateNetworkInterfaces()
	if shouldResetResolverForPathUpdate(wasInitialized, identityChanged, addressFamiliesChanged) {
		u.owe(func() { u.pendingResolver = true })
	}
	u.scheduleSettle(index)
	u.markSystemSubstitutes()
	log.Infoln("[Apple] default path -> %s (index=%d expensive=%v constrained=%v ipv4=%v ipv6=%v)",
		name, index, isExpensive, isConstrained, supportsIPv4, supportsIPv6)
}

const pathSettleDelay = 250 * time.Millisecond

func (u *interfaceUpdater) owe(mark func()) {
	u.settleMu.Lock()
	mark()
	u.settleMu.Unlock()
}

func (u *interfaceUpdater) scheduleSettle(index int32) {
	u.settleMu.Lock()
	if u.stopped || !(u.pendingFlows || u.pendingResolver || u.pendingWitness) {
		u.settleMu.Unlock()
		return
	}
	u.pendingIndex = index
	u.settleGen++
	gen := u.settleGen
	if u.settleStop != nil {
		u.settleStop()
	}
	u.settleMu.Unlock()
	stop := afterPathSettles(pathSettleDelay, func() { u.settle(gen) })
	u.settleMu.Lock()
	if gen == u.settleGen {
		u.settleStop = stop
	}
	u.settleMu.Unlock()
}

func (u *interfaceUpdater) settle(gen uint64) {
	u.settleMu.Lock()
	if u.stopped || gen != u.settleGen {
		u.settleMu.Unlock()
		return
	}
	flows, resolver, witnessOwed, index := u.pendingFlows, u.pendingResolver, u.pendingWitness, u.pendingIndex
	u.pendingFlows, u.pendingResolver, u.pendingWitness, u.settleStop = false, false, false, nil
	u.settleMu.Unlock()
	if flows {
		closeTrackedConnections()
		resetOutboundSessions()
	}
	if resolver {
		clearResolverCache()
		resetResolverConnection()
	}
	if witnessOwed {
		witnessPathChanged(index)
	}
}

func (u *interfaceUpdater) stopSettling() {
	u.settleMu.Lock()
	defer u.settleMu.Unlock()
	u.stopped = true
	u.settleGen++
	if u.settleStop != nil {
		u.settleStop()
		u.settleStop = nil
	}
}

func (u *interfaceUpdater) markSystemSubstitutes() {
	if u.publishLivePhysicalResolvers() {
		return
	}
	stale := u.name != u.initialName || u.index != u.initialIndex
	if !dns.SetSystemSubstitutesStale(stale) {
		return
	}
	substitutes := systemDNSServerSubstitutes()
	if len(substitutes) == 0 {
		return
	}
	if stale {
		log.Warnln("[Apple] default path left %s (index=%d) for %s (index=%d): the system resolvers the App read before the tunnel (%s) are not reachable from here and the extension cannot read this network's; every `system` nameserver falls back to the configuration's other resolvers in its slot, then the main nameservers, then the built-in pair, until the path returns",
			u.initialName, u.initialIndex, u.name, u.index, strings.Join(substitutes, ", "))
		return
	}
	log.Warnln("[Apple] default path is back on %s (index=%d): the system resolvers the App read before the tunnel (%s) answer `system` nameservers again",
		u.name, u.index, strings.Join(substitutes, ", "))
}

func (u *interfaceUpdater) publishLivePhysicalResolvers() bool {
	usable, _ := usableSystemResolverSubstitutes(readPhysicalResolvers(u.index), currentTunnelPrefixes())
	if len(usable) == 0 {
		if dns.SetSystemSubstituteServers(nil) {
			log.Warnln("[Apple] default path %s (index=%d) exposes no readable resolvers of its own; the resolvers read from the previous path are dropped and `system` nameservers fall back",
				u.name, u.index)
		}
		dns.SetSystemSubstitutesStale(u.name != u.initialName || u.index != u.initialIndex)
		return false
	}
	if !dns.SetSystemSubstituteServers(usable) {
		return true
	}
	dns.SetSystemSubstitutesStale(false)
	log.Warnln("[Apple] default path %s (index=%d) resolves `system` nameservers through %s, read from this network's scoped resolvers",
		u.name, u.index, strings.Join(usable, ", "))
	return true
}

func (u *interfaceUpdater) refreshLivePhysicalResolvers() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.initialized {
		return
	}
	if !dnsConfigurationChanged() {
		return
	}
	u.publishLivePhysicalResolvers()
}

func (u *interfaceUpdater) snapshot() interfaceUpdateSnapshot {
	u.mu.Lock()
	defer u.mu.Unlock()
	return interfaceUpdateSnapshot{
		received:         u.received,
		applied:          u.applied,
		identityChanges:  u.identityChanges,
		connectionResets: u.connectionResets,
	}
}

func startInterfaceMonitor(platform PlatformInterface) (InterfaceUpdateListener, error) {
	if platform == nil {
		return nil, nil
	}
	bindDefaultInterface := platform.UsePlatformAutoDetectInterfaceControl()
	monitorWithoutBinding := currentRuntimeProfile() == runtimeProfileMacOSPacketTunnel
	if !bindDefaultInterface && !monitorWithoutBinding {
		return nil, nil
	}
	listener := &interfaceUpdater{bindDefaultInterface: bindDefaultInterface}
	dns.SetSystemSubstitutesStale(false)
	dns.SetSystemSubstituteRefresh(listener.refreshLivePhysicalResolvers)
	if err := platform.StartDefaultInterfaceMonitor(listener); err != nil {
		dns.SetSystemSubstituteRefresh(nil)
		_ = platform.CloseDefaultInterfaceMonitor(listener)
		return nil, err
	}
	return listener, nil
}

func shouldResetResolverForPathUpdate(wasInitialized, identityChanged, addressFamiliesChanged bool) bool {
	return true
}
