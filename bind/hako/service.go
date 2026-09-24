package hako

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TokenPLS/Hako/component/pause"
	"github.com/TokenPLS/Hako/component/resolver"
	"github.com/TokenPLS/Hako/config"
	constant "github.com/TokenPLS/Hako/constant"
	provider "github.com/TokenPLS/Hako/constant/provider"
	"github.com/TokenPLS/Hako/dns"
	"github.com/TokenPLS/Hako/hub/executor"
	coreListener "github.com/TokenPLS/Hako/listener"
	LC "github.com/TokenPLS/Hako/listener/config"
	"github.com/TokenPLS/Hako/listener/inner"
	"github.com/TokenPLS/Hako/log"
	"github.com/TokenPLS/Hako/tunnel"
	"github.com/TokenPLS/Hako/tunnel/statistic"
	tun "github.com/metacubex/sing-tun"
	"golang.org/x/sys/unix"
)

var errNotImplemented = errors.New("hako: not implemented yet")

var activeCoreCount atomic.Int32

type BoxService struct {
	mu        sync.Mutex
	routingMu sync.Mutex
	platform  PlatformInterface
	running   bool
	stunMu       sync.Mutex
	stunClosing  bool
	stunNextID   uint64
	stunSessions map[uint64]context.CancelFunc
	stunWG       sync.WaitGroup
	tunFd int
	liveTunFd int
	liveTun    LC.Tun
	hasLiveTun bool
	ifaceListener         InterfaceUpdateListener
	logWriter             *platformLogWriter
	clashAPIPath          string
	startTimeUnix         int64
	inboundCount          int32
	outboundCount         int32
	dnsTransports         dnsTransportSnapshot
	outboundEndpointKinds map[string]string
	providerRuntime       *providerRuntime
	proxyShare            *proxyShareRuntime
	pauseCount            atomic.Uint64
	wakeCount             atomic.Uint64

	startFootprintBytes    int64
	configLength           int
	providerBytes          int64
	candidateProviderBytes int64
	reloadVerdict          reloadMemoryVerdict

	endPauseMu    sync.Mutex
	endPauseTimer *time.Timer
}

func NewService(platform PlatformInterface) (*BoxService, error) {
	if platform == nil {
		return nil, bridgeSafeError(errors.New("hako: NewService requires a platform"))
	}
	setupMu.Lock()
	ok := setupDone
	cacheDisabled := setupCacheDisabled
	setupMu.Unlock()
	if !ok {
		return nil, bridgeSafeError(errors.New("hako: call Setup before NewService"))
	}
	if cacheDisabled {
		return nil, bridgeSafeError(errors.New("hako: NewService is unavailable after App-only DisablePersistentCache Setup"))
	}
	platform = bridgeSafePlatform(platform)
	logWriter := redirectLogs(platform)
	armNEPacingForService(platform)
	installSocketHook(platform)
	setUnscopedResolversArePhysical(!platform.UnderNetworkExtension())
	installLocalZoneResolver(true)
	installNetworkInterfaceProvider(platform)
	installListenerScopeHooks(platform.UnderNetworkExtension())
	return &BoxService{platform: platform, tunFd: -1, liveTunFd: -1, logWriter: logWriter}, nil
}

func logFootprint(stage string) {
	footprint := MemoryFootprint()
	if footprint <= 0 {
		return
	}
	log.Infoln("[mem] %s: %.1f MiB of the extension's budget",
		stage, float64(footprint)/(1<<20))
}

func (s *BoxService) Start(configContent string) error {
	return bridgeSafeError(s.start(configContent))
}

func (s *BoxService) start(configContent string) (startErr error) {
	defer func() { recordStartupFailure(startErr) }()
	startupPhase("start-first-statement")
	defer armStartupProbes()()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return errors.New("hako: service already started")
	}
	startupPhase("validated")
	setupMu.Lock()
	activeCoreCount.Add(1)
	setupMu.Unlock()
	startupPhase("core-count-bumped")
	defer func() {
		if !s.running {
			activeCoreCount.Add(-1)
		}
	}()
	if s.logWriter == nil {
		s.logWriter = redirectLogs(s.platform)
	}
	startupPhase("logs-redirected")
	logFootprint("before the interface monitor")
	startupPhase("pre-iface-monitor")
	listener, err := startInterfaceMonitor(s.platform)
	if err != nil {
		return fmt.Errorf("hako: start default interface monitor: %w", err)
	}
	s.ifaceListener = listener
	startupPhase("iface-monitor-up")

	setStartupBreadcrumbRecording(currentRuntimePolicy(s.platform.UnderNetworkExtension()).networkExtension)
	startupStageCounting("bind:unmarshal-begin", int64(len(configContent)))
	var startedDNSTransports dnsTransportSnapshot
	startedOutboundEndpointKinds := snapshotOutboundEndpointKinds(configContent)
	var startedProviderRuntime *providerRuntime
	done := make(chan error, 1)
	var pendingTunOpen chan tunOpenResult
	go func() {
		defer func() {
			if r := recover(); r != nil {
				executor.WaitBeforeTunAttach = nil
				shutdownCore()
				stopClashAPI(s.clashAPIPath)
				s.clashAPIPath = ""
				closeFDIfOpen(s.tunFd)
				s.resetTunState()
				reapUnclaimedTunOpen(pendingTunOpen)
				if startedProviderRuntime != nil {
					startedProviderRuntime.close()
					startedProviderRuntime = nil
				}
				log.Errorln("[Apple] the start panicked and the tunnel did not come up: %v", r)
				done <- fmt.Errorf("hako: start panicked: %v", r)
			}
		}()
		startupPhase("pre-config-parse")
		debug.FreeOSMemory()
		s.startFootprintBytes = readFootprintForReload()
		s.configLength = len(configContent)
		s.providerBytes = providerPayloadBytes(configContent)
		logFootprint("before parsing the configuration")
		cfg, runtime, err := parseConfigForIOSRuntime(configContent, s.platform.UnderNetworkExtension(), deviationEntryStart)
		logFootprint("after parsing the configuration")
		startupPhase("config-parsed")
		if err != nil {
			startupPhase("config-refused")
			log.Errorln("[Apple] the configuration was refused and the tunnel did not start: %v", err)
			done <- err
			return
		}
		startedProviderRuntime = runtime
		fail := func(err error) {
			log.Errorln("[Apple] the tunnel did not start: %v", err)
			if startedProviderRuntime != nil {
				startedProviderRuntime.close()
				startedProviderRuntime = nil
			}
			done <- err
		}

		underNE := s.platform.UnderNetworkExtension()
		finalizeConfigForApple(cfg, currentRuntimePolicy(underNE))
		startedDNSTransports = snapshotDNSTransports(cfg)
		startupPhase("config-finalized")

		if cfg.General.Tun.Enable {
			startupPhase("tun-open-dispatched")
			pendingTunOpen = dispatchTunOpen(s.platform, &cfg.General.Tun)
			executor.WaitBeforeTunAttach = func(applied *config.Config) {
				result := <-pendingTunOpen
				pendingTunOpen = nil
				if result.err != nil {
					panic(fmt.Sprintf("hako: OpenTun: %v", result.err))
				}
				s.tunFd = result.fd
				s.liveTunFd = result.fd
				applied.General.Tun.FileDescriptor = result.fd
				startupPhase("tun-fd-ready")
			}
		}

		startupPhase("pre-apply-config")
		logFootprint("before applying it (providers load here)")
		executor.ApplyConfig(cfg, true)
		executor.WaitBeforeTunAttach = nil
		logFootprint("after applying it")
		startupPhase("apply-config-done")
		s.logWriter.markTunnelEstablished()
		pendingTunFd := s.tunFd
		s.tunFd = -1
		if cfg.General.Tun.Enable {
			if err := verifyTunStarted(cfg.General.Tun); err != nil {
				shutdownCore()
				closeFDIfOpen(pendingTunFd)
				s.resetTunState()
				fail(err)
				return
			}
			startupPhase("tun-verified")
		}
		if cfg.General.Tun.Enable {
			s.liveTun = cfg.General.Tun
			s.hasLiveTun = true
		}
		if underNE {
			s.clashAPIPath = ClashAPIPath()
			if err := startControlPlane(cfg, s.clashAPIPath); err != nil {
				shutdownCore()
				s.resetTunState()
				s.clashAPIPath = ""
				fail(err)
				return
			}
			startupPhase("clash-api-up")
		} else {
			applyExternalController(cfg)
		}
		done <- nil
	}()
	if err := <-done; err != nil {
		s.closeInterfaceMonitor()
		return err
	}

	startupPhase("start-return-begin")
	s.running = true
	markStartupComplete()
	s.resumeSTUNSessions()
	s.startTimeUnix = time.Now().Unix()
	s.inboundCount = runtimeInboundCount()
	s.outboundCount = int32(len(tunnel.Proxies()))
	s.dnsTransports = startedDNSTransports
	s.outboundEndpointKinds = startedOutboundEndpointKinds
	s.providerRuntime = startedProviderRuntime
	setOOMEvidenceCoreState(true, s.startTimeUnix, s.inboundCount, s.outboundCount)
	publishCoreService(s)
	startupPhase("start-return-done")
	return nil
}

type tunOpenResult struct {
	fd  int
	err error
}

func dispatchTunOpen(platform PlatformInterface, tun *LC.Tun) chan tunOpenResult {
	results := make(chan tunOpenResult, 1)
	options := tun
	go func() {
		fd, err := prepareTunBridgeFD(platform, options)
		results <- tunOpenResult{fd: fd, err: err}
	}()
	return results
}

func reapUnclaimedTunOpen(pending chan tunOpenResult) {
	if pending == nil {
		return
	}
	go func() {
		if result := <-pending; result.err == nil {
			closeFDIfOpen(result.fd)
		}
	}()
}

func prepareTunBridgeFD(platform PlatformInterface, tun *LC.Tun) (int, error) {
	fd, err := platform.OpenTun(newTunOptions(tun))
	if err != nil {
		return -1, fmt.Errorf("hako: OpenTun: %w", err)
	}
	if fd < 0 {
		return -1, fmt.Errorf("hako: OpenTun returned invalid bridge fd %d", fd)
	}
	dupFd, err := unix.Dup(int(fd))
	if err != nil {
		return -1, fmt.Errorf("hako: dup PacketFlow bridge fd %d: %w", fd, err)
	}
	return dupFd, nil
}

func verifyTunStarted(expected LC.Tun) error {
	actual := coreListener.GetTunConf()
	if !actual.Enable {
		return errors.New("hako: tun listener failed to start; inspect preceding core log for the underlying error")
	}
	if actual.FileDescriptor != expected.FileDescriptor {
		return fmt.Errorf("hako: tun listener fd mismatch: live=%d expected=%d", actual.FileDescriptor, expected.FileDescriptor)
	}
	return nil
}

func closeFDIfOpen(fd int) {
	if fd < 0 {
		return
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
		_ = unix.Close(fd)
	}
}

func (s *BoxService) resetTunState() {
	s.tunFd = -1
	s.liveTunFd = -1
	s.liveTun = LC.Tun{}
	s.hasLiveTun = false
}

func (s *BoxService) Reload(configContent string) error {
	s.stopSTUNSessions()
	defer s.resumeSTUNSessions()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return bridgeSafeError(errors.New("hako: Reload before Start"))
	}
	verdict := s.judgeReloadAgainstTheCeiling(configContent)
	if verdict.Reason == reloadRefusedMemory {
		return bridgeSafeError(reloadMemoryRefusal(verdict))
	}
	ticket := beginReloadEvidence(verdict)
	defer endReloadEvidence(ticket)
	done := make(chan error, 1)
	go func() {
		var nextProviderRuntime *providerRuntime
		committedProviderRuntime := false
		defer func() {
			if r := recover(); r != nil {
				if !committedProviderRuntime && nextProviderRuntime != nil {
					nextProviderRuntime.close()
					nextProviderRuntime = nil
				}
				log.Errorln("[Apple] the reload panicked and the tunnel did not come up: %v", r)
				done <- fmt.Errorf("hako: reload panicked: %v", r)
			}
		}()
		underNE := s.platform.UnderNetworkExtension()
		cfg, runtime, err := parseConfigForIOSRuntime(configContent, underNE, deviationEntryReload)
		if err != nil {
			log.Errorln("[Apple] the replacement configuration was refused and the running one is unchanged: %v", err)
			done <- err
			return
		}
		nextProviderRuntime = runtime
		fail := func(err error) {
			log.Errorln("[Apple] the reload did not complete and the running configuration is unchanged: %v", err)
			if nextProviderRuntime != nil {
				nextProviderRuntime.close()
				nextProviderRuntime = nil
			}
			done <- err
		}
		finalizeConfigForApple(cfg, currentRuntimePolicy(underNE))
		if cfg.General.Tun.Enable {
			if s.liveTunFd < 0 {
				fail(errors.New("hako: reload enables tun but no live fd from Start"))
				return
			}
			cfg.General.Tun.FileDescriptor = s.liveTunFd
		}
		if cfg.General.Tun.Enable != s.hasLiveTun {
			fail(errors.New("hako: reload cannot enable or disable the live tun; restart the appex"))
			return
		}
		if s.hasLiveTun && !tunConfigurationsEqual(s.liveTun, cfg.General.Tun) {
			fail(errors.New("hako: reload changes the effective tun; restart the appex instead of rebuilding utun"))
			return
		}
		advanceReloadEvidence(ticket, reloadPhaseApply)
		func() {
			s.routingMu.Lock()
			defer s.routingMu.Unlock()
			executor.ApplyConfig(cfg, false)
			applyExternalController(cfg)
		}()
		if err := s.reapplyProxyShareLocked(); err != nil {
			log.Errorln("[iOS] proxy share closed after reload: %v", err)
			_ = s.stopProxyShareLocked()
		}
		previousProviderRuntime := s.providerRuntime
		s.providerRuntime = nextProviderRuntime
		committedProviderRuntime = true
		if previousProviderRuntime != nil {
			previousProviderRuntime.close()
		}
		s.inboundCount = s.runtimeInboundCountLocked()
		s.outboundCount = int32(len(tunnel.Proxies()))
		s.dnsTransports = snapshotDNSTransports(cfg)
		s.outboundEndpointKinds = snapshotOutboundEndpointKinds(configContent)
		s.configLength = len(configContent)
		if s.candidateProviderBytes >= 0 {
			s.providerBytes = s.candidateProviderBytes
		} else {
			s.providerBytes = providerPayloadBytes(configContent)
		}
		setOOMEvidenceCoreState(true, s.startTimeUnix, s.inboundCount, s.outboundCount)
		debug.FreeOSMemory()
		done <- nil
	}()
	return bridgeSafeError(<-done)
}

func runtimeInboundCount() int32 {
	count := len(tunnel.Listeners())
	ports := coreListener.GetPorts()
	for _, port := range []int{ports.Port, ports.SocksPort, ports.RedirPort, ports.TProxyPort, ports.MixedPort} {
		if port != 0 {
			count++
		}
	}
	if ports.ShadowSocksConfig != "" {
		count++
	}
	if ports.VmessConfig != "" {
		count++
	}
	if coreListener.GetTuicConf().Enable {
		count++
	}
	if coreListener.GetTunConf().Enable {
		count++
	}
	return int32(count)
}

func runGuardedTeardown(teardown func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Warnln("[iOS] core teardown recovered from panic: %v", r)
		}
	}()
	teardown()
}

func (s *BoxService) Close() error {
	s.stopSTUNSessions()
	s.releasePauseOnClose()
	s.mu.Lock()
	defer s.mu.Unlock()
	unpublishCoreService(s)
	if !s.running {
		s.stopProxyShareLocked()
		s.closeInterfaceMonitor()
		stopClashAPI(s.clashAPIPath)
		s.clashAPIPath = ""
		stopLogRedirect(s.logWriter)
		s.logWriter = nil
		if s.providerRuntime != nil {
			s.providerRuntime.close()
			s.providerRuntime = nil
		}
		return nil
	}
	s.stopProxyShareLocked()
	s.closeInterfaceMonitor()
	stopClashAPI(s.clashAPIPath)
	s.clashAPIPath = ""
	done := make(chan struct{})
	go func() {
		defer close(done)
		runGuardedTeardown(func() {
			shutdownCore()
			debug.FreeOSMemory()
		})
	}()
	<-done
	if s.providerRuntime != nil {
		s.providerRuntime.close()
		s.providerRuntime = nil
	}
	if s.tunFd >= 0 {
		_ = unix.Close(s.tunFd)
		s.tunFd = -1
	}
	s.resetTunState()
	s.running = false
	s.startTimeUnix = 0
	s.inboundCount = 0
	s.outboundCount = 0
	s.dnsTransports = dnsTransportSnapshot{}
	s.outboundEndpointKinds = nil
	activeCoreCount.Add(-1)
	setOOMEvidenceCoreState(false, 0, 0, 0)
	stopLogRedirect(s.logWriter)
	s.logWriter = nil
	return nil
}

func (s *BoxService) closeInterfaceMonitor() {
	if s.ifaceListener == nil {
		return
	}
	listener := s.ifaceListener
	s.ifaceListener = nil
	if updater, ok := listener.(*interfaceUpdater); ok {
		updater.stopSettling()
	}
	dns.SetSystemSubstituteRefresh(nil)
	installLocalZoneResolver(false)
	if err := s.platform.CloseDefaultInterfaceMonitor(listener); err != nil {
		log.Warnln("[iOS] close interface monitor: %v", err)
	}
	pause.NetworkWake()
	publishedInterfaceIndex.Store(0)
	witness.reset()
}

func shutdownCore() {
	inner.CloseTCPConnections()
	CloseAllConnections()

	proxies := tunnel.Proxies()
	providers := tunnel.Providers()
	ruleProviders := tunnel.RuleProviders()
	tunnel.UpdateProxies(map[string]constant.Proxy{}, map[string]provider.ProxyProvider{})
	tunnel.UpdateRules(nil, map[string][]constant.Rule{}, map[string]provider.RuleProvider{})

	executor.Shutdown()
	resolver.ResetConnection()
	resolver.CloseQueries()

	for _, current := range providers {
		if closer, ok := any(current).(io.Closer); ok {
			_ = closer.Close()
		}
	}
	for _, current := range ruleProviders {
		if closer, ok := any(current).(io.Closer); ok {
			_ = closer.Close()
		}
	}
	for _, current := range proxies {
		_ = current.Close()
	}
}

func (s *BoxService) RuntimeDiagnosticsJSON() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	connectionCount := int32(0)
	statistic.DefaultManager.Range(func(statistic.Tracker) bool {
		connectionCount++
		return true
	})
	runtimeSetup := runtimeSetupSnapshot()
	memory := currentRuntimeMemorySnapshot()
	nat64 := nat64DiagnosticsSnapshot()
	admission := tunnel.TCPConnectionAdmissionSnapshot()
	diagnostics := map[string]any{
		"processIdentifier":                   os.Getpid(),
		"startTimeUnix":                       s.startTimeUnix,
		"goroutines":                          runtime.NumGoroutine(),
		"inboundCount":                        s.inboundCount,
		"outboundCount":                       s.outboundCount,
		"dnsMainTransportTypes":               s.dnsTransports.main,
		"dnsFallbackTransportTypes":           s.dnsTransports.fallback,
		"dnsDefaultTransportTypes":            s.dnsTransports.defaults,
		"dnsProxyTransportTypes":              s.dnsTransports.proxyServer,
		"dnsDirectTransportTypes":             s.dnsTransports.direct,
		"dnsPolicyTransportTypes":             s.dnsTransports.policy,
		"outboundEndpointKinds":               s.outboundEndpointKinds,
		"connectionCount":                     connectionCount,
		"tcpConnectionAdmissionLimit":         admission.Limit,
		"tcpConnectionAdmissionActive":        admission.Active,
		"tcpConnectionAdmissionRejectedTotal": admission.Rejected,
		"running":                             s.running,
		"pauseCount":                          s.pauseCount.Load(),
		"wakeCount":                           s.wakeCount.Load(),
		"gcPercent":                           runtimeSetup.gcPercent,
		"logMaxLines":                         runtimeSetup.logMaxLines,
		"availableMemoryBytes":                memory.availableBytes,
		"physicalMemoryBytes":                 memory.physicalBytes,
		"goRuntimeResidentBytes":              memory.goResidentBytes,
		"nonGoPhysicalEstimateBytes":          memory.nonGoPhysicalEstimate,
		"goHeapAllocBytes":                    memory.heapAllocBytes,
		"goHeapInuseBytes":                    memory.heapInuseBytes,
		"goStackInuseBytes":                   memory.stackInuseBytes,
		"goGCCount":                           memory.gcCount,
		"goGCPauseTotalNanoseconds":           memory.gcPauseTotalNanoseconds,
		"processCPUTimeNanoseconds":           processCPUTimeNanoseconds(),
		"goMaxProcs":                          runtime.GOMAXPROCS(0),
		"memoryPressureEventCount":            memoryPressureEventCount.Load(),
		"physicalPathSupportsIPv4":            nat64.supportsIPv4,
		"physicalPathSupportsIPv6":            nat64.supportsIPv6,
		"nat64SynthesisAttempts":              nat64.attempts,
		"nat64SynthesisApplied":               nat64.applied,
		"nat64SynthesisFailures":              nat64.failures,
	}
	if runtimeSetup.softMemoryLimit > 0 {
		diagnostics["softMemoryLimit"] = runtimeSetup.softMemoryLimit
	}
	if conf := coreListener.GetTunConf(); conf.Enable {
		diagnostics["tunStack"] = conf.Stack.String()
	}
	if s.reloadVerdict.Reason != "" {
		diagnostics["reloadVerdict"] = s.reloadVerdict
	}
	for key, value := range pressureThresholdDiagnostics() {
		diagnostics[key] = value
	}
	if snapshot := tun.GVisorTCPWindowSnapshot; snapshot != nil {
		window := snapshot()
		diagnostics["gvisorTCPWindowMinBytes"] = window.MinBytes
		diagnostics["gvisorTCPWindowDefaultBytes"] = window.DefaultBytes
		diagnostics["gvisorTCPWindowMaxBytes"] = window.MaxBytes
		diagnostics["gvisorTCPWindowConnections"] = window.TCPConnections
		diagnostics["gvisorTCPReceiveOccupancyP50Bytes"] = window.ReceiveOccupancyP50Bytes
		diagnostics["gvisorTCPReceiveOccupancyP95Bytes"] = window.ReceiveOccupancyP95Bytes
		diagnostics["gvisorTCPReceiveOccupancyMaxBytes"] = window.ReceiveOccupancyMaxBytes
		diagnostics["gvisorTCPConnectionsNearReceiveMax"] = window.ConnectionsNearReceiveMax
		diagnostics["gvisorTCPSegmentQueueDroppedTotal"] = window.SegmentQueueDroppedTotal
	}
	if updater, ok := s.ifaceListener.(*interfaceUpdater); ok {
		path := updater.snapshot()
		diagnostics["physicalPathUpdatesReceived"] = path.received
		diagnostics["physicalPathUpdatesApplied"] = path.applied
		diagnostics["physicalPathIdentityChanges"] = path.identityChanges
		diagnostics["physicalPathConnectionResets"] = path.connectionResets
	}
	if snapshot := tun.GVisorPacketIOSnapshot; snapshot != nil {
		packetIO := snapshot()
		diagnostics["corePacketIngressReadCalls"] = packetIO.IngressReadCalls
		diagnostics["corePacketIngressReadWouldBlock"] = packetIO.IngressReadWouldBlock
		diagnostics["corePacketIngressReadPackets"] = packetIO.IngressReadPackets
		diagnostics["corePacketIngressReadBytes"] = packetIO.IngressReadBytes
		diagnostics["corePacketIngressReadErrors"] = packetIO.IngressReadErrors
		diagnostics["corePacketIngressDispatchPackets"] = packetIO.IngressDispatchPackets
		diagnostics["corePacketIngressDispatchBytes"] = packetIO.IngressDispatchBytes
		diagnostics["corePacketProcessorQueueDepth"] = packetIO.ProcessorQueueDepth
		diagnostics["corePacketProcessorQueuePeak"] = packetIO.ProcessorQueuePeak
		diagnostics["corePacketEgressWriteCalls"] = packetIO.EgressWriteCalls
		diagnostics["corePacketEgressWritePackets"] = packetIO.EgressWritePackets
		diagnostics["corePacketEgressWriteBytes"] = packetIO.EgressWriteBytes
		diagnostics["corePacketEgressWriteErrors"] = packetIO.EgressWriteErrors
		diagnostics["corePacketEgressWriteWaits"] = packetIO.EgressWriteWaits
		diagnostics["corePacketEgressWriteWaitExhausted"] = packetIO.EgressWriteWaitExhausted
	}
	tunEgress := tun.TunEgressSnapshot()
	diagnostics["coreTunEgressWriteWaits"] = tunEgress.WriteWaits
	diagnostics["coreTunEgressWriteWaitExhausted"] = tunEgress.WriteWaitExhausted
	deferred := tun.DeferredHandshakeSnapshot()
	diagnostics["coreDeferredHandshakes"] = deferred.Deferred
	diagnostics["coreDeferredHandshakesBudgetSpent"] = deferred.BudgetSpent
	diagnostics["coreDeferredHandshakesCompleted"] = deferred.Completed
	diagnostics["coreDeferredHandshakesCompletedLate"] = deferred.CompletedLate
	diagnostics["coreDeferredHandshakesNotCompleted"] = deferred.NotCompleted
	diagnostics["coreDeferredHandshakesRefused"] = deferred.Refused
	diagnostics["coreDeferredHandshakesPending"] = deferred.Pending
	return bridgeSafeString(mustJSON(diagnostics))
}

func finalizeConfigForIOS(cfg *config.Config, underNE bool) {
	finalizeConfigForApple(cfg, runtimePolicyFor(runtimeProfileIOSPacketTunnel, underNE))
}

func finalizeConfigForApple(cfg *config.Config, policy appleRuntimePolicy) {
	if policy.networkExtension && policy.packetTunnel {
		ensureTunEnabled(&cfg.General.Tun)
	}
	overrideForAppleConfig(cfg, policy)
	if policy.networkExtension {
		overrideForNetworkExtension(cfg)
	}
}

func tunConfigurationsEqual(left, right LC.Tun) bool {
	left = cloneTunSlices(left)
	right = cloneTunSlices(right)
	left.Sort()
	right.Sort()
	sortTunFieldsMissingFromUpstream(&left)
	sortTunFieldsMissingFromUpstream(&right)
	return left.Equal(right) &&
		slices.Equal(left.LoopbackAddress, right.LoopbackAddress) &&
		slices.Equal(left.ExcludeSrcPort, right.ExcludeSrcPort) &&
		slices.Equal(left.ExcludeSrcPortRange, right.ExcludeSrcPortRange) &&
		slices.Equal(left.ExcludeDstPort, right.ExcludeDstPort) &&
		slices.Equal(left.ExcludeDstPortRange, right.ExcludeDstPortRange)
}

func cloneTunSlices(tun LC.Tun) LC.Tun {
	tun.DNSHijack = slices.Clone(tun.DNSHijack)
	tun.Inet4Address = slices.Clone(tun.Inet4Address)
	tun.Inet6Address = slices.Clone(tun.Inet6Address)
	tun.LoopbackAddress = slices.Clone(tun.LoopbackAddress)
	tun.RouteAddress = slices.Clone(tun.RouteAddress)
	tun.RouteAddressSet = slices.Clone(tun.RouteAddressSet)
	tun.RouteExcludeAddress = slices.Clone(tun.RouteExcludeAddress)
	tun.RouteExcludeAddressSet = slices.Clone(tun.RouteExcludeAddressSet)
	tun.IncludeInterface = slices.Clone(tun.IncludeInterface)
	tun.ExcludeInterface = slices.Clone(tun.ExcludeInterface)
	tun.IncludeUID = slices.Clone(tun.IncludeUID)
	tun.IncludeUIDRange = slices.Clone(tun.IncludeUIDRange)
	tun.ExcludeUID = slices.Clone(tun.ExcludeUID)
	tun.ExcludeUIDRange = slices.Clone(tun.ExcludeUIDRange)
	tun.ExcludeSrcPort = slices.Clone(tun.ExcludeSrcPort)
	tun.ExcludeSrcPortRange = slices.Clone(tun.ExcludeSrcPortRange)
	tun.ExcludeDstPort = slices.Clone(tun.ExcludeDstPort)
	tun.ExcludeDstPortRange = slices.Clone(tun.ExcludeDstPortRange)
	tun.IncludeAndroidUser = slices.Clone(tun.IncludeAndroidUser)
	tun.IncludePackage = slices.Clone(tun.IncludePackage)
	tun.ExcludePackage = slices.Clone(tun.ExcludePackage)
	tun.IncludeMACAddress = slices.Clone(tun.IncludeMACAddress)
	tun.ExcludeMACAddress = slices.Clone(tun.ExcludeMACAddress)
	tun.Inet4RouteAddress = slices.Clone(tun.Inet4RouteAddress)
	tun.Inet6RouteAddress = slices.Clone(tun.Inet6RouteAddress)
	tun.Inet4RouteExcludeAddress = slices.Clone(tun.Inet4RouteExcludeAddress)
	tun.Inet6RouteExcludeAddress = slices.Clone(tun.Inet6RouteExcludeAddress)
	return tun
}

func sortTunFieldsMissingFromUpstream(tun *LC.Tun) {
	slices.SortFunc(tun.LoopbackAddress, func(left, right netip.Addr) int {
		return left.Compare(right)
	})
	slices.Sort(tun.ExcludeSrcPort)
	slices.Sort(tun.ExcludeSrcPortRange)
	slices.Sort(tun.ExcludeDstPort)
	slices.Sort(tun.ExcludeDstPortRange)
}

func (s *BoxService) Status() string {
	return bridgeSafeString(tunnel.Status().String())
}

func (s *BoxService) Mode() string {
	s.routingMu.Lock()
	defer s.routingMu.Unlock()
	return bridgeSafeString(tunnel.Mode().String())
}

func (s *BoxService) SetMode(mode string) error {
	m, ok := tunnel.ModeMapping[strings.ToLower(mode)]
	if !ok {
		return bridgeSafeError(fmt.Errorf("hako: unknown mode %q", mode))
	}
	s.routingMu.Lock()
	defer s.routingMu.Unlock()
	tunnel.SetMode(m)
	return nil
}

const endPauseTimeout = time.Minute

func (s *BoxService) releasePauseOnClose() {
	s.endPauseMu.Lock()
	if s.endPauseTimer != nil {
		s.endPauseTimer.Stop()
	}
	s.endPauseMu.Unlock()

	if s.pauseCount.Load() > s.wakeCount.Load() {
		pause.DeviceWake()
	}
}

func (s *BoxService) Pause() {
	s.pauseCount.Add(1)
	pause.DevicePause()
	s.armEndPauseTimer()
	debug.FreeOSMemory()
}

func (s *BoxService) armEndPauseTimer() {
	if !currentRuntimeProfile().inheritsIOSPacketTunnelBehavior() {
		return
	}
	s.endPauseMu.Lock()
	defer s.endPauseMu.Unlock()
	if s.endPauseTimer == nil {
		s.endPauseTimer = time.AfterFunc(endPauseTimeout, pause.DeviceWake)
		return
	}
	s.endPauseTimer.Reset(endPauseTimeout)
}

func (s *BoxService) Wake() {
	s.wakeCount.Add(1)
	pause.DeviceWake()
	resolver.ResetConnection()
}
