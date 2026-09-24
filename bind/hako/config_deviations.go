package hako

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/TokenPLS/Hako/log"
	"gopkg.in/yaml.v3"
)

const (
	deviationStripped    = "stripped"
	deviationForced      = "forced"
	deviationUnavailable = "unavailable"
)

const configDeviationSchemaVersion = 1

type configDeviation struct {
	Field string `json:"field"`
	Given string `json:"given"`
	Effective string `json:"effective"`
	Category string `json:"category"`
	Reason string `json:"reason"`
	Source string `json:"source"`
	Recoverable bool `json:"recoverable"`
	Alternative string `json:"alternative,omitempty"`
	Effect string `json:"effect,omitempty"`
	Mechanism string `json:"mechanism,omitempty"`
	Written bool `json:"written"`
	UpstreamDefault string `json:"upstreamDefault,omitempty"`
	RuleKind string `json:"ruleKind,omitempty"`
	Honoured bool `json:"honoured,omitempty"`
}

type deviationRule struct {
	field       string
	category    string
	effective   string
	reason      string
	source      string
	recoverable bool
	alternative string
	withheld bool
	ruleScan bool
	ruleKind string
	applies func(policy appleRuntimePolicy) bool
	upstreamDefault string
	honouredBy string
	defaultOnly bool
	forcedValue string
	// mechanism is the developer's half of the reason: the file, function, API type, kernel
	// constant or tool that makes the sentence true. It exists so that reason can be written
	// for the person changing a setting -- what happened to them, what they can do -- while the
	// material that proves it lives here. Clients keep mechanism and source for the diagnostics
	// export and never put them on screen. The user's words on seeing
	// "bind/hako/config_pipeline.go:119-124 (the StoreFakeIPSet guard)" under a setting: that is
	// Go's decision-making shown to someone who came to change a setting.
	mechanism string
}

const (
	tunPacketTunnelShape = "on Apple the tunnel is the only shape this extension can take, so there is no setting that turns it off"
	tunRoutingIsApples   = "on Apple the routes are installed by the app, not by the core, so the core-side routing switches have nothing to act on"
	tunOffloadBridge   = "on Apple the tunnel has no network driver to negotiate offload with, so offload cannot be turned on"
	tunBatchIOBridge   = "on Apple the tunnel does not expose the batched read/write path these fields select, so the ordinary path is used instead; nothing is lost but the batching"
	tunAutoRouteFilter = "this filters a kind of routing the core never installs on Apple -- the app installs the routes -- so there is nothing for the filter to act on"

	tunPacketTunnelShapeMechanism = "a packet tunnel provider is a tun by construction: there is no no-tun shape for the extension to take"
	tunRoutingIsApplesMechanism   = "routes belong to NEPacketTunnelNetworkSettings and are installed by the extension's Swift side; the core does not own a host routing table here"
	tunOffloadBridgeMechanism     = "the data plane is NEPacketTunnelFlow bridged through a SOCK_DGRAM descriptor rather than a utun fd; segmentation offload is negotiated with a tun driver, and the bridge descriptor has no such driver to negotiate with"
	tunBatchIOBridgeMechanism     = "the data plane is NEPacketTunnelFlow bridged through a SOCK_DGRAM descriptor rather than a utun fd, so the batched utun-fd read/write path these fields select uses ordinary readv/writev instead (this is about the fd, not about socket options -- IP_BOUND_IF is a socket option and works fine over the bridge)"
	tunAutoRouteFilterMechanism   = "this filters sing-tun's auto-route host routing, which the extension never installs -- NEPacketTunnelNetworkSettings does"

	tunIncludeAllNetworks          = "with Include All Networks on, the system and mixed stacks send nothing; only the gvisor stack carries the tunnel's traffic"
	tunIncludeAllNetworksMechanism = "Include All Networks makes the kernel drop, at ip_output, every packet that does not leave through the tunnel; the system and mixed stacks re-inject the tunnel's TCP through the kernel and lose it there, which is why sing-tun refuses both under includeAllNetworks (third_party/sing-tun/stack.go)"
)

func underNetworkExtension(policy appleRuntimePolicy) bool { return policy.networkExtension }

func underPacketTunnel(policy appleRuntimePolicy) bool {
	return policy.networkExtension && policy.packetTunnel
}

var deviationRules = []deviationRule{
	{
		field:       "tproxy-port",
		category:    deviationUnavailable,
		effective:   "no transparent-proxy listener is opened",
		reason:      "transparent proxying is a Linux-only facility; the core itself reports it as unsupported on this platform",
		source:      "upstream listener/tproxy/setsockopt_other.go; iPhoneOS SDK netinet/in.h has no IP_TRANSPARENT",
		recoverable: false,
		mechanism:   "transparent proxying needs Linux netfilter; upstream's own non-Linux build answers \"not supported on current platform\"",
	},
	{
		field:       "redir-port",
		category:    deviationUnavailable,
		effective:   "no redirect listener is opened",
		reason:      "the redirect listener needs a system facility that an app on Apple is not allowed to open, and a firewall rule the app is not allowed to install",
		source:      "upstream listener/redir/tcp_darwin.go; /System/Library/Sandbox/Profiles/application.sb",
		recoverable: false,
		mechanism:   "upstream's darwin implementation reads the original destination from /dev/pf with a DIOCNATLOOK ioctl, which an App Sandbox cannot open, and installing the pf redirect rule it depends on needs root",
	},
	{
		field:       "dns.listen-routing-mark",
		category:    deviationUnavailable,
		effective:   "the mark is not applied",
		reason:      "socket marks are a Linux facility and do not exist on Apple",
		source:      "iPhoneOS SDK sys/socket.h defines no SO_MARK",
		recoverable: false,
		mechanism:   "SO_MARK is a Linux socket option and does not exist on Darwin",
	},
	{
		field:       "external-controller-routing-mark",
		category:    deviationUnavailable,
		effective:   "the mark is not applied",
		reason:      "socket marks are a Linux facility and do not exist on Apple",
		source:      "iPhoneOS SDK sys/socket.h defines no SO_MARK",
		recoverable: false,
		mechanism:   "SO_MARK is a Linux socket option and does not exist on Darwin",
	},
	{
		field:     "external-controller-pipe",
		category:  deviationUnavailable,
		effective: "no pipe is opened",
		reason: "a named pipe is a Windows facility; upstream requires the address to start " +
			"with \\\\.\\pipe\\ and has no Darwin implementation",
		source:      "upstream hub/route/server.go:308",
		recoverable: false,
	},
	{
		field:     "allow-lan",
		category:  deviationStripped,
		effective: "the configured listener stays on 127.0.0.1 instead of every interface",
		reason: "exposing the device to the local network is a decision the person holding it " +
			"makes, not one an imported subscription makes for them; the app has not recorded " +
			"that agreement yet",
		source: "listener/listener.go:709-718 genAddr binds \":port\" when allow-lan is true and " +
			"127.0.0.1 when it is not; bind/hako/allow_lan_gate.go holds the permission",
		recoverable: false,
		alternative: "turn on local-network sharing in the app; the configured value is honoured from the next reload",
		applies: func(policy appleRuntimePolicy) bool {
			return policy.networkExtension && !allowLanPermitted.Load()
		},
	},
	{
		field:     "rules",
		ruleScan:  true,
		ruleKind:  "UID",
		category:  deviationUnavailable,
		effective: "UID rules are removed; a logic rule carrying a UID branch is removed whole",
		reason: "UID names a socket owner this platform does not expose, and the core's own rule " +
			"constructor refuses to build it here, so keeping the rule would fail the entire " +
			"configuration rather than simply never matching",
		source: "upstream rules/common/uid.go gates NewUid on GOOS linux/android/darwin; " +
			"rules/logic/logic.go parsePayload returns on the first branch that fails to construct",
		recoverable: false,
		applies: func(policy appleRuntimePolicy) bool {
			return policy.networkExtension && !policy.processMetadata().resolves("UID")
		},
	},
	{
		field:     "tun.route-address-set",
		category:  deviationUnavailable,
		effective: "the routes take effect: the named rule set is read and its addresses are written into route-address before the core starts; the set name itself is accepted and ignored, the same as on any other platform",
		reason:    "the named rule set is turned into plain addresses before the core starts, so the routes you meant do take effect; the set itself is a Linux firewall facility that Apple does not have",
		source: "bind/hako/config_finalize.go FinalizeForIOS expandRouteSet; sing-tun consumes the " +
			"field itself only in redirect_linux.go and redirect_nftables*.go, always through " +
			"autoRedirect, and upstream documentation says Linux only and requires nftables",
		recoverable: false,
		honouredBy:  "expansion",
		mechanism:   "the FIELD is a Linux forwarding-plane switch -- it adds prefixes to an nftables set so the host firewall can bypass the redirect -- but the INTENT behind it, which prefixes enter the tunnel, is expressible here and is honoured by expanding it",
	},
	{
		field:     "tun.route-exclude-address-set",
		category:  deviationUnavailable,
		effective: "the exclusions take effect: the named rule set is read and its addresses are written into route-exclude-address before the core starts; the set name itself is accepted and ignored, the same as on any other platform",
		reason:    "the named rule set is turned into plain addresses before the core starts, so the routes you meant do take effect; the set itself is a Linux firewall facility that Apple does not have",
		source: "bind/hako/config_finalize.go FinalizeForIOS expandRouteSet; sing-tun consumes the " +
			"field itself only in redirect_linux.go and redirect_nftables*.go, always through " +
			"autoRedirect, and upstream documentation says Linux only and requires nftables",
		recoverable: false,
		honouredBy:  "expansion",
		mechanism:   "the FIELD is a Linux forwarding-plane switch -- it adds prefixes to an nftables set so the host firewall can bypass the redirect -- but the INTENT behind it, which prefixes enter the tunnel, is expressible here and is honoured by expanding it",
	},
	{
		field:       "ntp.write-to-system",
		category:    deviationForced,
		effective:   "false: the core keeps its own NTP offset and never sets the device clock",
		reason:      "only the system itself may set the device clock; an app or its extension cannot",
		source:      "man 2 settimeofday: \"Only the super-user may set the time of day\" (EPERM otherwise)",
		recoverable: false,
		forcedValue: "false",
		applies:   underNetworkExtension,
		mechanism: "setting the system clock goes through settimeofday, which only the super-user may call; an app extension is not",
	},

	{
		field:       "routing-mark",
		category:    deviationUnavailable,
		effective:   "no mark is set on outbound sockets",
		reason:      "socket marks are a Linux facility and do not exist on Apple; the core itself reports it as unsupported here",
		source:      "upstream component/dialer/mark_nonlinux.go printMarkWarn; Darwin has no SO_MARK",
		recoverable: false,
		mechanism:   "SO_MARK is a Linux socket option; upstream's own non-Linux build warns \"Routing mark on socket is not supported on current platform\" and sets nothing",
	},


	{
		field:     "interface-name",
		category:  deviationStripped,
		effective: "removed: outbound sockets are bound by the extension, not by this name",
		reason:    "on Apple every outgoing connection is already bound to the physical network by the app, so a name here has nothing left to decide; this is a choice of this product, not a platform limit",
		source: "bind/hako/override.go overrideForNetworkExtension; upstream " +
			"component/dialer/dialer.go \"ignore interfaceName, routingMark when " +
			"DefaultSocketHook not null\"; component/dialer/bind_darwin.go exists",
		recoverable: false,
		applies:     underNetworkExtension,
		mechanism:   "the extension installs a socket hook so every outbound socket is bound to the physical interface with IP_BOUND_IF, and upstream's dialer ignores interface-name whenever a socket hook is installed -- unlike routing-mark this one is a decision, because binding by name does work on Darwin without the hook",
	},

	{
		field:     "dns.enable",
		category:  deviationForced,
		effective: "true: the core serves DNS for the queries the tunnel captures",
		reason: "an Apple packet tunnel always captures port 53; with dns.enable false the core " +
			"serves nothing and every captured query answers SERVFAIL, so the tunnel would " +
			"start and resolve nothing",
		source:          "upstream config/config.go DefaultRawConfig has DNS.Enable false",
		recoverable:     false,
		applies:         underNetworkExtension,
		upstreamDefault: "false",
		forcedValue:     "true",
	},
	{
		field:     "profile.store-fake-ip",
		category:  deviationForced,
		effective: "true: fake-ip mappings are written to disk so they survive an extension restart",
		reason: "an Apple packet tunnel is restarted by the system far more often than a desktop " +
			"process is, and a fresh in-memory pool hands the same domain a different fake " +
			"address each time; an explicit true or false is always honoured",
		source:          "bind/hako/config_pipeline.go:119-124 (the StoreFakeIPSet guard); upstream config/config.go DefaultRawConfig has StoreFakeIP false",
		recoverable:     true,
		alternative:     "write profile.store-fake-ip explicitly -- any value you set is kept",
		upstreamDefault: "false",
		defaultOnly:     true,
		forcedValue:     "true",
	},
	{
		field:     "unified-delay",
		category:  deviationForced,
		effective: "true: a probe reports the second, comparable round trip instead of billing the whole cold start to whichever proxy was measured first",
		reason: "upstream defaults unified-delay off, so the first probe of a proxy pays " +
			"TCP, TLS and the protocol handshake while the next one does not, and numbers " +
			"cannot be compared across proxies or protocols; an explicit true or false is " +
			"always honoured",
		source:          "bind/hako/config_pipeline.go applyUnifiedDelayDefault (the typed-probe guard); upstream config/config.go DefaultRawConfig has UnifiedDelay false",
		recoverable:     true,
		alternative:     "write unified-delay explicitly -- any value you set is kept",
		upstreamDefault: "false",
		defaultOnly:     true,
		forcedValue:     "true",
	},
	{
		field:     "find-process-mode",
		category:  deviationForced,
		effective: "off: no rule is matched against the owning process, and PROCESS-*/UID rules evaluate against empty metadata",
		reason: "an app extension cannot enumerate other processes, so a lookup would fail on " +
			"every connection rather than some; the rules themselves are kept and behave " +
			"exactly as they do with find-process-mode off",
		source:          "upstream config/config.go DefaultRawConfig has FindProcessMode strict; bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces",
		recoverable:     false,
		applies:         func(policy appleRuntimePolicy) bool { return !policy.processMetadata().processPath },
		upstreamDefault: "strict",
		forcedValue:     "off",
	},
	{
		field:       "tun.stack",
		category:    deviationForced,
		effective:   "gvisor: the only stack that carries traffic while Include All Networks is on",
		reason:      tunIncludeAllNetworks,
		source:      "bind/hako/override.go overrideTunForIOS; third_party/sing-tun/stack.go ErrIncludeAllNetworks; NETunnelProviderProtocol.includeAllNetworks",
		recoverable: true,
		alternative: "turn Include All Networks off in the tunnel settings, or write tun.stack: gvisor",
		applies: func(policy appleRuntimePolicy) bool {
			return underPacketTunnel(policy) && includeAllNetworksActive()
		},
		forcedValue: "gvisor",
		mechanism:   tunIncludeAllNetworksMechanism,
	},
	{
		field:       "tun.enable",
		category:    deviationForced,
		effective:   "true: the extension is a packet tunnel, so it always carries a tun",
		reason:      tunPacketTunnelShape,
		source:      "bind/hako/service.go ensureTunEnabled",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "true",
		mechanism:   tunPacketTunnelShapeMechanism,
	},
	{
		field:       "tun.device",
		category:    deviationForced,
		effective:   "hako-packet-flow, this product's bridge",
		reason:      "on Apple the tunnel is handed to the core by the system, not opened by name, so there is no device to name",
		source:      "bind/hako/override.go overrideTunForIOS; Apple NEPacketTunnelProvider.packetFlow",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "hako-packet-flow",
		mechanism:   "the extension is handed an NEPacketTunnelFlow rather than a utun descriptor, so a device name has nothing to name",
	},
	{
		field:       "tun.auto-route",
		category:    deviationForced,
		effective:   "false: Swift installs the routes",
		reason:      tunRoutingIsApples,
		source:      "bind/hako/override.go overrideTunForIOS; Apple NEPacketTunnelNetworkSettings",
		recoverable: false,
		alternative: "tun.route-address and tun.route-exclude-address ARE honoured, and become the routes the extension installs",
		applies:     underPacketTunnel,
		forcedValue: "false",
		mechanism:   tunRoutingIsApplesMechanism,
	},
	{
		field:       "tun.auto-detect-interface",
		category:    deviationForced,
		effective:   "false: the extension decides its own egress interface",
		reason:      tunRoutingIsApples,
		source:      "bind/hako/override.go overrideTunForIOS; Apple NEPacketTunnelNetworkSettings",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "false",
		mechanism:   tunRoutingIsApplesMechanism,
	},
	{
		field:       "tun.gso",
		category:    deviationForced,
		effective:   "false",
		reason:      tunOffloadBridge,
		source:      "bind/hako/override.go overrideTunForIOS",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "false",
		mechanism:   tunOffloadBridgeMechanism,
	},
	{
		field:       "tun.gso-max-size",
		category:    deviationForced,
		effective:   "0, following gso",
		reason:      tunOffloadBridge,
		source:      "bind/hako/override.go overrideTunForIOS",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "0",
		mechanism:   tunOffloadBridgeMechanism,
	},
	{
		field:       "tun.recvmsgx",
		category:    deviationForced,
		effective:   "false: the tunnel uses its normal data path",
		reason:      tunBatchIOBridge,
		source:      "bind/hako/override.go overrideTunForIOS; upstream sing-tun recvmsg_x is the batched utun-fd read path, not a socket option",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "false",
		mechanism:   tunBatchIOBridgeMechanism,
	},
	{
		field:       "tun.sendmsgx",
		category:    deviationForced,
		effective:   "false: the tunnel uses its normal data path",
		reason:      tunBatchIOBridge,
		source:      "bind/hako/override.go overrideTunForIOS; upstream sing-tun sendmsg_x is the batched utun-fd write path, not a socket option",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "false",
		mechanism:   tunBatchIOBridgeMechanism,
	},
	{
		field:     "tun.disable-icmp-forwarding",
		category:  deviationForced,
		effective: "true: the core answers pings itself instead of forwarding them",
		reason: "forwarding ICMP needs a raw socket, which no unprivileged Apple process can " +
			"open; ping still answers, but the latency it shows is this device's, not the route's",
		source:      "bind/hako/override.go overrideTunForIOS; listener/sing_tun/prepare.go",
		recoverable: false,
		applies:     underPacketTunnel,
		forcedValue: "true",
	},
	{
		field:       "tun.dns-hijack",
		category:    deviationForced,
		effective:   "0.0.0.0:53, every DNS query in the tunnel",
		reason:      "this is a choice of this product, not an Apple rule: the system advertises one DNS address to apps, and capturing every DNS query is what keeps a query from slipping out of the tunnel unresolved",
		source:      "bind/hako/override.go overrideTunForIOS",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   "this is a product decision rather than an Apple rule: NEDNSSettings advertises one address, the tun gateway +1, and hijacking all of port 53 is what keeps a query from leaving the tunnel unresolved by this core",
	},
	{
		field:       "tun.include-interface",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-interface",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.include-uid",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.include-uid-range",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-uid",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-uid-range",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-src-port",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-src-port-range",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-dst-port",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-dst-port-range",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.include-mac-address",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.exclude-mac-address",
		category:    deviationStripped,
		effective:   "removed: nothing filters the tunnel by this",
		reason:      tunAutoRouteFilter,
		source:      "bind/hako/config_pipeline.go normalizeRawNetworkExtensionSurfaces; Apple NEPacketTunnelNetworkSettings owns the routes",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   tunAutoRouteFilterMechanism,
	},
	{
		field:       "tun.mtu",
		category:    deviationForced,
		effective:   "the MTU the extension selected at startup",
		reason:      "the tunnel can only use one packet size, and the app and the core have to agree on it, so it is chosen once at startup; a value written here is not used, and the size that is used is the one both sides agreed on, so nothing is missing",
		source:      "bind/hako/override.go overrideTunForIOS; TunOptions.GetMTU",
		recoverable: false,
		applies:     underPacketTunnel,
		mechanism:   "the core and the Network Extension have to agree on one number -- Swift reads it back through TunOptions.GetMTU and installs it on NEPacketTunnelNetworkSettings -- so a value that reached only one of the two would describe a link neither side is running",
	},
	{
		field:       "geo-auto-update",
		category:    deviationForced,
		effective:   "false: geo data is pre-downloaded by the containing app and handed to the core",
		reason:      "this is how this product is built, not an Apple rule: the app downloads geo data itself and hands it to the core",
		source:      "bind/hako/override.go",
		recoverable: false,
		forcedValue: "false",
		mechanism:   "this is this product's architecture, not an Apple rule -- an extension is allowed to make outbound requests",
	},
	{
		field:       "geodata-loader",
		category:    deviationForced,
		effective:   "memconservative: geo data is streamed rather than held decoded",
		reason:      "this core measured a 72.7 MiB peak compiling geosite, which a packet tunnel cannot afford; note that no Apple document states a memory ceiling",
		source:      "bind/hako/override.go; measured in this repository, not an Apple source",
		recoverable: false,
		forcedValue: "memconservative",
		applies: func(policy appleRuntimePolicy) bool { return policy.memoryConservativeGeodata },
	},
	{
		field:       "geo-update-interval",
		category:    deviationUnavailable,
		effective:   "unused: no periodic downloader runs in this core",
		reason:      "it only schedules geo-auto-update, which is off",
		source:      "bind/hako/override.go; see geo-auto-update",
		recoverable: false,
	},
	{
		field:       "tun.auto-redirect",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this configures a Linux-only part of the system that Apple does not have; the core accepts it and does nothing with it, exactly as it does on any non-Linux platform",
		source:      "sing-tun consumes it only in tun_linux.go and the redirect_nftables/iptables files, all Linux forwarding plane",
		recoverable: false,
		mechanism:   "this configures the Linux forwarding plane (nftables/iptables/iproute2), which no Apple platform has",
	},
	{
		field:       "tun.auto-redirect-input-mark",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this configures a Linux-only part of the system that Apple does not have; the core accepts it and does nothing with it, exactly as it does on any non-Linux platform",
		source:      "sing-tun consumes it only in tun_linux.go and the redirect_nftables/iptables files, all Linux forwarding plane",
		recoverable: false,
		mechanism:   "this configures the Linux forwarding plane (nftables/iptables/iproute2), which no Apple platform has",
	},
	{
		field:       "tun.auto-redirect-output-mark",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this configures a Linux-only part of the system that Apple does not have; the core accepts it and does nothing with it, exactly as it does on any non-Linux platform",
		source:      "sing-tun consumes it only in tun_linux.go and the redirect_nftables/iptables files, all Linux forwarding plane",
		recoverable: false,
		mechanism:   "this configures the Linux forwarding plane (nftables/iptables/iproute2), which no Apple platform has",
	},
	{
		field:       "tun.auto-redirect-iproute2-fallback-rule-index",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this configures a Linux-only part of the system that Apple does not have; the core accepts it and does nothing with it, exactly as it does on any non-Linux platform",
		source:      "sing-tun consumes it only in tun_linux.go and the redirect_nftables/iptables files, all Linux forwarding plane",
		recoverable: false,
		mechanism:   "this configures the Linux forwarding plane (nftables/iptables/iproute2), which no Apple platform has",
	},
	{
		field:       "tun.iproute2-table-index",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this configures a Linux-only part of the system that Apple does not have; the core accepts it and does nothing with it, exactly as it does on any non-Linux platform",
		source:      "sing-tun consumes it only in tun_linux.go and the redirect_nftables/iptables files, all Linux forwarding plane",
		recoverable: false,
		mechanism:   "this configures the Linux forwarding plane (nftables/iptables/iproute2), which no Apple platform has",
	},
	{
		field:       "tun.iproute2-rule-index",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this configures a Linux-only part of the system that Apple does not have; the core accepts it and does nothing with it, exactly as it does on any non-Linux platform",
		source:      "sing-tun consumes it only in tun_linux.go and the redirect_nftables/iptables files, all Linux forwarding plane",
		recoverable: false,
		mechanism:   "this configures the Linux forwarding plane (nftables/iptables/iproute2), which no Apple platform has",
	},
	{
		field:       "iptables",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this configures a Linux-only part of the system that Apple does not have; the core accepts it and does nothing with it, exactly as it does on any non-Linux platform",
		source:      "sing-tun consumes it only in tun_linux.go and the redirect_nftables/iptables files, all Linux forwarding plane",
		recoverable: false,
		mechanism:   "this configures the Linux forwarding plane (nftables/iptables/iproute2), which no Apple platform has",
	},
	{
		field:       "tun.include-package",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this names Android packages or users, which no Apple platform can resolve",
		source:      "resolving a package name to a UID exists only in sing-tun's packages_android.go; every other platform gets the packages_stub.go stub",
		recoverable: false,
	},
	{
		field:       "tun.exclude-package",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this names Android packages or users, which no Apple platform can resolve",
		source:      "resolving a package name to a UID exists only in sing-tun's packages_android.go; every other platform gets the packages_stub.go stub",
		recoverable: false,
	},
	{
		field:       "tun.include-android-user",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this names Android packages or users, which no Apple platform can resolve",
		source:      "resolving a package name to a UID exists only in sing-tun's packages_android.go; every other platform gets the packages_stub.go stub",
		recoverable: false,
	},
	{
		field:       "clash-for-android",
		category:    deviationUnavailable,
		effective:   "accepted and ignored, the same as on any other platform",
		reason:      "this names Android packages or users, which no Apple platform can resolve",
		source:      "resolving a package name to a UID exists only in sing-tun's packages_android.go; every other platform gets the packages_stub.go stub",
		recoverable: false,
	},
}

func collectConfigDeviations(mergedYAML string, policy appleRuntimePolicy) ([]configDeviation, error) {
	var root map[string]any
	if err := yaml.Unmarshal([]byte(mergedYAML), &root); err != nil {
		return nil, err
	}
	deviations := make([]configDeviation, 0)
	for _, rule := range deviationRules {
		if rule.applies != nil && !rule.applies(policy) {
			continue
		}
		if rule.ruleScan {
			continue
		}
		given, written := lookupYAMLPath(root, rule.field)
		if rule.defaultOnly && written {
			continue
		}
		if written && rule.forcedValue != "" && given == rule.forcedValue {
			continue
		}
		if written && rule.field == "tun.dns-hijack" && dnsHijackAlreadyHijacksAll(root) {
			continue
		}
		if written && rule.withheld {
			given = deviationValueWithheld
		}
		upstreamDefault := ""
		if !written {
			if rule.upstreamDefault == "" {
				continue
			}
			given = "not set (core default: " + rule.upstreamDefault + ")"
			upstreamDefault = rule.upstreamDefault
		}
		deviations = append(deviations, configDeviation{
			Field:           rule.field,
			Given:           given,
			Effective:       rule.effective,
			Category:        rule.category,
			Reason:          rule.reason,
			Source:          rule.source,
			Recoverable:     rule.recoverable,
			Alternative:     rule.alternative,
			Mechanism:       rule.mechanism,
			Written:         written,
			UpstreamDefault: upstreamDefault,
			Honoured:        rule.honouredBy != "",
		})
	}
	deviations = append(deviations, ownerMetadataRuleDeviations(root, policy)...)
	return deviations, nil
}

func ownerMetadataRuleDeviations(root map[string]any, policy appleRuntimePolicy) []configDeviation {
	if !policy.networkExtension {
		return nil
	}
	rules, _ := root["rules"].([]any)
	capability := policy.processMetadata()

	reported := make([]configDeviation, 0)
	inertKinds := make(map[string]int)
	firstInert := make(map[string]string)
	for index, entry := range rules {
		text, isString := entry.(string)
		if !isString {
			continue
		}
		kind, _ := splitRuleKindAndPattern(text)
		if matchesMetadataRuleKindName(kind) == "" || capability.resolves(kind) {
			continue
		}
		switch ownerMetadataRuleEffect(text) {
		case RuleEffectMatchesEverything:
			reported = append(reported, configDeviation{
				Field:     fmt.Sprintf("rules[%d]", index),
				Given:     text,
				Effective: "this rule matches every connection on this platform, with its action unchanged",
				Category:  deviationUnavailable,
				Effect:    RuleEffectMatchesEverything,
				Reason: "the pattern matches an empty process name, and this platform supplies " +
					"none, so a rule written to single out one process is now the broadest rule " +
					"in the file",
				Source:      "upstream rules/common/process.go Match compares the pattern against metadata.Process, which no Apple packet tunnel populates",
				Recoverable: true,
				Written:     true,
				RuleKind:    kind,
				Alternative: "anchor the pattern so it cannot match an empty name, or remove the rule",
			})
		case RuleEffectNeverMatches:
			if _, seen := inertKinds[kind]; !seen {
				firstInert[kind] = fmt.Sprintf("rules[%d]", index)
			}
			inertKinds[kind]++
		}
	}
	for kind, count := range inertKinds {
		field := "rules"
		given := fmt.Sprintf("%d rule(s), first at %s", count, firstInert[kind])
		if count == 1 {
			given = firstInert[kind]
		}
		reported = append(reported, configDeviation{
			Field:       field,
			Given:       given,
			Effective:   "these rules never match on this platform; traffic falls through to the next rule",
			Category:    deviationUnavailable,
			Effect:      RuleEffectNeverMatches,
			Reason:      "the metadata they test is not available to an Apple packet tunnel, so the comparison never succeeds",
			Source:      "upstream rules/common Match reads metadata this platform does not populate; the rules are kept rather than removed so logic rules keep their executable branches",
			Recoverable: false,
			Written:     true,
			RuleKind:    kind,
		})
	}
	if !capability.resolves("UID") {
		if registration := deviationRuleByKind("UID"); registration != nil &&
			(registration.applies == nil || registration.applies(policy)) {
			count, first := uidRuleOccurrences(root)
			if count > 0 {
				given := fmt.Sprintf("%d rule(s), first at %s", count, first)
				if count == 1 {
					given = first
				}
				reported = append(reported, configDeviation{
					Field:       registration.field,
					Given:       given,
					Effective:   registration.effective,
					Category:    registration.category,
					Reason:      registration.reason,
					Source:      registration.source,
					Recoverable: registration.recoverable,
					Alternative: registration.alternative,
					Mechanism:   registration.mechanism,
					Written:     true,
					RuleKind:    registration.ruleKind,
				})
			}
		}
	}
	sort.Slice(reported, func(i, j int) bool {
		if reported[i].Field != reported[j].Field {
			return reported[i].Field < reported[j].Field
		}
		return reported[i].RuleKind < reported[j].RuleKind
	})
	return reported
}

func deviationRuleByKind(kind string) *deviationRule {
	for i := range deviationRules {
		if deviationRules[i].ruleScan && deviationRules[i].ruleKind == kind {
			return &deviationRules[i]
		}
	}
	return nil
}

func deviationRuleByField(field string) *deviationRule {
	for i := range deviationRules {
		if deviationRules[i].field == field {
			return &deviationRules[i]
		}
	}
	return nil
}

func uidRuleOccurrences(root map[string]any) (count int, first string) {
	scan := func(entries []any, location func(int) string) {
		for index, entry := range entries {
			text, isString := entry.(string)
			if !isString || !ruleCarriesUID(text) {
				continue
			}
			if count == 0 {
				first = location(index)
			}
			count++
		}
	}
	rules, _ := root["rules"].([]any)
	scan(rules, func(i int) string { return fmt.Sprintf("rules[%d]", i) })
	if subRules, ok := root["sub-rules"].(map[string]any); ok {
		names := make([]string, 0, len(subRules))
		for name := range subRules {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			list, _ := subRules[name].([]any)
			scan(list, func(i int) string { return fmt.Sprintf("sub-rules.%s[%d]", name, i) })
		}
	}
	return count, first
}

func lookupYAMLPath(root map[string]any, path string) (string, bool) {
	current := any(root)
	for _, segment := range strings.Split(path, ".") {
		node, isMap := current.(map[string]any)
		if !isMap {
			return "", false
		}
		value, present := node[segment]
		if !present {
			return "", false
		}
		current = value
	}
	if current == nil {
		return "", false
	}
	return renderDeviationValue(current), true
}

const deviationValueWithheld = "set (value withheld)"

func renderDeviationValue(value any) string {
	switch typed := value.(type) {
	case string:
		if typed == "" {
			return `""`
		}
		return typed
	case []any:
		return fmt.Sprintf("%d entries", len(typed))
	case map[string]any:
		return fmt.Sprintf("%d keys", len(typed))
	default:
		return fmt.Sprintf("%v", typed)
	}
}

var publishedDeviations atomic.Pointer[publishedDeviationReport]

const (
	deviationEntryStart  = "start"
	deviationEntryReload = "reload"
)

type deviationDocumentIdentity struct {
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type publishedDeviationReport struct {
	Sequence uint64
	Entry      string
	Document   deviationDocumentIdentity
	Deviations []configDeviation
}

var deviationPublishSequence atomic.Uint64

func publishDeviations(entry, content string, deviations []configDeviation) *publishedDeviationReport {
	sum := sha256.Sum256([]byte(content))
	report := &publishedDeviationReport{
		Sequence:   deviationPublishSequence.Add(1),
		Entry:      entry,
		Document:   deviationDocumentIdentity{Bytes: len(content), SHA256: hex.EncodeToString(sum[:])},
		Deviations: deviations,
	}
	publishedDeviations.Store(report)
	log.Infoln("[Apple] deviations published: entry=%s seq=%d document=%dB sha256=%s rows=%d",
		entry, report.Sequence, report.Document.Bytes, report.Document.SHA256[:16], len(deviations))
	for _, deviation := range deviations {
		log.Warnln("[Apple] deviation %s: given=%q effective=%q category=%s -- %s",
			deviation.Field, deviation.Given, deviation.Effective, deviation.Category, deviationWhy(deviation))
	}
	return report
}

func deviationWhy(deviation configDeviation) string {
	if deviation.Mechanism != "" {
		return deviation.Mechanism
	}
	return deviation.Reason
}

func loadPublishedDeviationReport() *publishedDeviationReport {
	return publishedDeviations.Load()
}

func loadPublishedDeviations() []configDeviation {
	if report := publishedDeviations.Load(); report != nil {
		return report.Deviations
	}
	return []configDeviation{}
}

func dnsHijackAlreadyHijacksAll(root map[string]any) bool {
	tun, _ := root["tun"].(map[string]any)
	list, ok := tun["dns-hijack"].([]any)
	if !ok || len(list) != 1 {
		return false
	}
	v, _ := list[0].(string)
	return v == "0.0.0.0:53" || v == "any:53"
}
