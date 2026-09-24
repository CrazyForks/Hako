package hako

import (
	"sync"

	"github.com/TokenPLS/Hako/component/dialer"
	"github.com/TokenPLS/Hako/component/iface"
	"github.com/TokenPLS/Hako/component/resolver"
	"github.com/TokenPLS/Hako/log"
)

type interfaceUpdater struct {
	mu                   sync.Mutex
	bindDefaultInterface bool
	initialized          bool
	name                 string
	index                int32
	isExpensive          bool
	isConstrained        bool
	supportsIPv4         bool
	supportsIPv6         bool
	received             uint64
	applied              uint64
	identityChanges      uint64
	connectionResets     uint64
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
		return
	}
	u.applied++
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
	if wasInitialized && (identityChanged || addressFamiliesChanged) {
		if identityChanged {
			u.identityChanges++
		}
		u.connectionResets++
		closeTrackedConnections()
	}
	flushInterfaceCache()
	if shouldResetResolverForPathUpdate(wasInitialized, identityChanged, addressFamiliesChanged) {
		clearResolverCache()
		resetResolverConnection()
	}
	log.Infoln("[Apple] default path -> %s (index=%d expensive=%v constrained=%v ipv4=%v ipv6=%v)",
		name, index, isExpensive, isConstrained, supportsIPv4, supportsIPv6)
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
	if err := platform.StartDefaultInterfaceMonitor(listener); err != nil {
		_ = platform.CloseDefaultInterfaceMonitor(listener)
		return nil, err
	}
	return listener, nil
}

func shouldResetResolverForPathUpdate(wasInitialized, identityChanged, addressFamiliesChanged bool) bool {
	return true
}
