package hako

import (
	"net"

	"github.com/TokenPLS/Hako/component/process"
	"github.com/TokenPLS/Hako/config"
	C "github.com/TokenPLS/Hako/constant"
	LC "github.com/TokenPLS/Hako/listener/config"
)

func overrideForIOS(cfg *config.Config) {
	overrideForAppleConfig(cfg, runtimePolicyFor(runtimeProfileIOSPacketTunnel, false))
}

func overrideForAppleConfig(cfg *config.Config, policy appleRuntimePolicy) {
	cfg.General.GeoAutoUpdate = false

	if !policy.processMetadata().processPath {
		cfg.General.FindProcessMode = process.FindProcessOff
	}

	if policy.memoryConservativeGeodata {
		cfg.General.GeodataLoader = "memconservative"
	}

	if cfg.Controller != nil {
		_ = cfg.Controller
	}

	if policy.packetTunnel && cfg.General.Tun.Enable {
		overrideTunForIOS(&cfg.General.Tun)
	}
}

func overrideForNetworkExtension(cfg *config.Config) {
	if cfg.General != nil {
		cfg.General.RedirPort = 0
		cfg.General.TProxyPort = 0
		cfg.General.Interface = ""
		cfg.General.RoutingMark = 0
	}
	if cfg.DNS != nil {
		cfg.DNS.ListenRoutingMark = 0
	}
	if cfg.IPTables != nil {
		cfg.IPTables.Enable = false
	}
	if cfg.NTP != nil {
		cfg.NTP.WriteToSystem = false
	}
}

func ensureTunEnabled(tun *LC.Tun) {
	tun.Enable = true
}

func overrideTunForIOS(tun *LC.Tun) {
	tun.Device = packetFlowBridgeDevice
	if includeAllNetworksActive() && (tun.Stack == C.TunSystem || tun.Stack == C.TunMixed) {
		tun.Stack = C.TunGvisor
	}
	tun.MTU = uint32(effectiveTunMTU())
	tun.AutoRoute = false
	tun.AutoDetectInterface = false
	tun.GSO = false
	tun.GSOMaxSize = 0
	tun.RecvMsgX = false
	tun.SendMsgX = false
	tun.DisableICMPForwarding = true

	tun.DNSHijack = []string{"0.0.0.0:53"}
}

func dnsHijackCovers(tun *LC.Tun) bool {
	for _, h := range tun.DNSHijack {
		if h == "0.0.0.0:53" || h == "any:53" {
			return true
		}
	}
	dns, err := newTunOptions(tun).GetDNSServerAddress()
	if err != nil {
		return false
	}
	for _, h := range tun.DNSHijack {
		if host, _, splitErr := net.SplitHostPort(h); splitErr == nil && host == dns.Value {
			return true
		}
	}
	return false
}
