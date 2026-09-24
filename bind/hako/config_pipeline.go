package hako

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"net"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/TokenPLS/Hako/common/orderedmap"
	"github.com/TokenPLS/Hako/component/geodata"
	"github.com/TokenPLS/Hako/component/process"
	"github.com/TokenPLS/Hako/config"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/dns"
	"github.com/TokenPLS/Hako/log"
)

const disabledGeoURL = "hako-ne-disabled://prestage-required"

func parseConfigForIOS(content string, underNE bool) (*config.Config, error) {
	cfg, _, err := parseConfigForIOSInternal(content, underNE, false)
	return cfg, err
}

func parseConfigForIOSRuntime(content string, underNE bool, entry string) (*config.Config, *providerRuntime, error) {
	cfg, runtime, err := parseConfigForIOSInternal(content, underNE, true)
	if err != nil {
		return cfg, runtime, err
	}
	deviations, deviationErr := collectConfigDeviations(content, currentRuntimePolicy(underNE))
	if deviationErr != nil {
		log.Warnln("[Apple] could not compute the configuration deviation report: %v", deviationErr)
	} else {
		publishDeviations(entry, content, deviations)
	}
	return cfg, runtime, nil
}

func parseConfigForIOSInternal(content string, underNE bool, stageRuntime bool) (*config.Config, *providerRuntime, error) {
	if err := validateConfigurationInput(content); err != nil {
		return nil, nil, err
	}
	raw, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		return nil, nil, fmt.Errorf("hako: parse config: %w", err)
	}
	startupStage("bind:unmarshalled")
	canonicalizeProviderDefinitionKeys(raw)
	policy := currentRuntimePolicy(underNE)
	if policy.networkExtension {
		if err := validateRawNetworkExtensionIntentForApple(raw, policy); err != nil {
			return nil, nil, err
		}
	}
	normalizeRawConfigForApple(raw, policy)
	startupStage("bind:normalized")
	applyStoreFakeIPDefault(raw)
	applyUnifiedDelayDefault(raw, configExplicitlySetsUnifiedDelay([]byte(content)))
	startupStage("bind:fakeip-default")
	if err := validateRawConfigForIOS(raw); err != nil {
		return nil, nil, err
	}
	startupStage("bind:ios-validated")
	var runtime *providerRuntime
	if stageRuntime {
		runtime, err = stageProviderRuntime(raw, policy, false)
		if err != nil {
			return nil, nil, err
		}
	} else {
		stripProviderSideUpdateMetadata(raw)
	}
	startupStage("bind:providers-staged")

	cfg, err := parseRawConfigQuietly(raw)
	if err != nil {
		if runtime != nil {
			runtime.close()
		}
		return nil, nil, fmt.Errorf("hako: parse config: %w", explainInvalidDomainPatterns(raw, err))
	}
	startupStage("bind:apple-validate-in")
	if err := validateForApple(cfg, raw, policy); err != nil {
		if runtime != nil {
			runtime.close()
		}
		return nil, nil, err
	}
	return cfg, runtime, nil
}

func canonicalizeProviderDefinitionKeys(raw *config.RawConfig) {
	if raw == nil {
		return
	}
	for _, namespace := range []map[string]map[string]any{raw.ProxyProvider, raw.RuleProvider} {
		for _, definition := range namespace {
			if definition == nil {
				continue
			}
			for key, value := range definition {
				lowered := strings.ToLower(key)
				if lowered == key {
					continue
				}
				if _, exists := definition[lowered]; !exists {
					definition[lowered] = value
				}
				delete(definition, key)
			}
		}
	}
}

func canonicalizeProviderDefinitionKeysInDocument(root map[string]any) {
	for _, namespace := range []string{"proxy-providers", "rule-providers"} {
		providers, ok := root[namespace].(map[string]any)
		if !ok {
			continue
		}
		for _, raw := range providers {
			definition, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			for key, value := range definition {
				lowered := strings.ToLower(key)
				if lowered == key {
					continue
				}
				if _, exists := definition[lowered]; !exists {
					definition[lowered] = value
				}
				delete(definition, key)
			}
		}
	}
}

func applyStoreFakeIPDefault(raw *config.RawConfig) {
	if raw.Profile.StoreFakeIPSet {
		return
	}
	raw.Profile.StoreFakeIP = true
}

func applyUnifiedDelayDefault(raw *config.RawConfig, explicitlySet bool) {
	if explicitlySet {
		return
	}
	raw.UnifiedDelay = true
}

func configExplicitlySetsUnifiedDelay(content []byte) bool {
	var probe struct {
		UnifiedDelay *bool `yaml:"unified-delay"`
	}
	if err := yaml.Unmarshal(content, &probe); err != nil {
		return false
	}
	return probe.UnifiedDelay != nil
}


func normalizeRawConfigForIOS(raw *config.RawConfig, underNE bool) {
	normalizeRawConfigForApple(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, underNE))
}

func normalizeRawConfigForApple(raw *config.RawConfig, policy appleRuntimePolicy) {
	if policy.memoryConservativeGeodata {
		raw.GeodataLoader = "memconservative"
	}
	geodata.SetCompiledGeoSiteOnly(policy.compiledGeoSiteOnly)
	geodata.SetCompiledGeoIPOnly(policy.compiledGeoIPOnly)
	setStartupBreadcrumbRecording(policy.networkExtension)
	if policy.networkExtension {
		geodata.SetGeodataProgressReporter(recordStartupResource)
	} else {
		geodata.SetGeodataProgressReporter(nil)
	}
	raw.GeoAutoUpdate = false
	raw.GeoXUrl = config.RawGeoXUrl{
		GeoIp:   disabledGeoURL,
		Mmdb:    disabledGeoURL,
		ASN:     disabledGeoURL,
		GeoSite: disabledGeoURL,
	}
	if policy.networkExtension {
		normalizeRawNetworkExtensionSurfaces(raw, policy.processMetadata())
		if supplied := systemDNSServerSubstitutes(); len(supplied) != 0 {
			usable, dropped := usableSystemResolverSubstitutes(supplied, tunnelPrefixesFromRaw(raw))
			if len(dropped) != 0 {
				log.Warnln("[Apple %s] DNS SystemDNSServerLines %s fall inside this configuration's own tunnel ranges and are ignored: the App read the system resolvers after the tunnel's DNS settings applied", policy.profile.String(), strings.Join(dropped, ", "))
			}
			for _, change := range substituteSystemResolvers(raw, usable) {
				log.Warnln("[Apple %s] DNS %s %s resolves through the system resolvers the App read before the tunnel: %s", policy.profile.String(), change.where(), change.entry, strings.Join(usable, ", "))
			}
		}
		for _, ns := range stripNEIncompatibleNameservers(raw) {
			log.Warnln("[Apple %s] DNS %s cannot work from a packet tunnel (system resolves only to the tunnel's own DNS address, which mihomo blacklists, so it yields nothing; dhcp:// must bind 0.0.0.0:68 on a physical interface -- unverified); stripped, resolution stays inside the core and the config still starts", policy.profile.String(), ns)
		}
		if policy.repairPacketTunnelDNS {
			for _, repair := range repairApplePacketTunnelDNS(raw) {
				log.Warnln("[Apple %s] DNS %s", policy.profile.String(), repair)
			}
			if !raw.DNS.Enable {
				log.Warnln("[Apple %s] DNS is disabled by this configuration. Inside a packet "+
					"tunnel that means name resolution will not work: the core stops serving "+
					"DNS while the tunnel still captures port 53, which is also what mihomo "+
					"does with tun and dns.enable false. Set dns.enable true to resolve names.",
					policy.profile.String())
			}
		}
		for _, ns := range detectUnroutableDNSFragments(raw) {
			log.Warnln("[Apple %s] DNS %s names a physical interface or an unknown proxy in its fragment; kept as-is — it will fail closed at runtime unless the name materializes (config still starts)", policy.profile.String(), ns)
		}
		for _, field := range stripOutboundEgressOverrides(raw) {
			log.Warnln("[Apple %s] outbound egress override %s has no Network Extension equivalent and is stripped; the config still starts", policy.profile.String(), field)
		}
		capability := policy.processMetadata()
		if !capability.resolves("UID") || !uidRuleConstructible(runtime.GOOS) {
			for _, occurrence := range summarizeOccurrenceList(stripUnconstructibleUIDRules(raw)) {
				log.Warnln("[Apple %s] %s: %s", policy.profile.String(), occurrence, uidRuleExplanation)
			}
		}
		for _, notice := range unguardedControllerNotices(raw) {
			log.Warnln("[Apple %s] %s", policy.profile.String(), notice)
		}
		for _, notice := range unauthenticatedLANListenerNotices(raw) {
			log.Warnln("[Apple %s] %s", policy.profile.String(), notice)
		}
		for _, rule := range summarizeMetadataRuleOccurrences(raw, capability) {
			log.Warnln("[Apple %s] %s: %s", policy.profile.String(), rule, metadataRuleKeptExplanation)
		}
	}
}

func unauthenticatedLANListenerNotices(raw *config.RawConfig) []string {
	notices := make([]string, 0, 4)
	if raw.AllowLan && !authenticationCoversRemoteSources(raw) {
		for _, listener := range []struct {
			field string
			port  int
		}{{"port", raw.Port}, {"socks-port", raw.SocksPort}, {"mixed-port", raw.MixedPort}} {
			if listener.port != 0 {
				notices = append(notices, fmt.Sprintf(
					"%s %d is reachable from the local network with allow-lan and no effective authentication: "+
						"any device on any network this one joins can use it as a proxy. Set "+
						"authentication, or lan-allowed-ips, to narrow it",
					listener.field, listener.port))
			}
		}
	}
	if len(raw.Listeners) > 0 {
		notices = append(notices, fmt.Sprintf(
			"listeners declares %d inbound listener(s), each on its own listen address — "+
				"upstream defaults that to 0.0.0.0, and the allow-lan permission does not cover it. "+
				"Every device on every network this one joins can reach them unless each entry "+
				"names a narrower listen address and its own authentication",
			len(raw.Listeners)))
	}
	if len(raw.Tunnels) > 0 {
		notices = append(notices, fmt.Sprintf(
			"tunnels declares %d static tunnel listener(s), which are opened as written and are "+
				"not covered by the allow-lan permission", len(raw.Tunnels)))
	}
	for _, server := range []struct {
		field   string
		present bool
	}{
		{"ss-config", strings.TrimSpace(raw.ShadowSocksConfig) != ""},
		{"vmess-config", strings.TrimSpace(raw.VmessConfig) != ""},
		{"tuic-server", raw.TuicServer.Enable},
	} {
		if server.present {
			notices = append(notices, fmt.Sprintf(
				"%s starts a protocol server on this device, opened as written and not covered by "+
					"the allow-lan permission; its listen address is the one that entry names",
				server.field))
		}
	}
	return notices
}

func authenticationCoversRemoteSources(raw *config.RawConfig) bool {
	if len(raw.Authentication) == 0 {
		return false
	}
	for _, prefix := range raw.SkipAuthPrefixes {
		if !prefix.Addr().IsLoopback() || prefix.Bits() == 0 {
			return false
		}
	}
	return true
}

func unguardedControllerNotices(raw *config.RawConfig) []string {
	if raw.Secret != "" {
		return nil
	}
	notices := make([]string, 0, 2)
	for _, endpoint := range []struct {
		field   string
		address string
	}{{"external-controller", raw.ExternalController}, {"external-controller-tls", raw.ExternalControllerTLS}} {
		if endpoint.address == "" || isLoopbackListenAddress(endpoint.address) {
			continue
		}
		notices = append(notices, fmt.Sprintf(
			"%s listens on %s with no secret: anything that can reach it can change proxies, "+
				"rules and mode on the running tunnel, and can switch allow-lan on -- which "+
				"makes this device an open proxy for whoever is on the same network. "+
				"Set secret, or bind it to 127.0.0.1",
			endpoint.field, endpoint.address))
	}
	return notices
}

func isLoopbackListenAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	switch host {
	case "127.0.0.1", "::1", "localhost", "[::1]":
		return true
	default:
		return false
	}
}

func normalizeRawNetworkExtensionSurfaces(raw *config.RawConfig, capability appleProcessMetadataCapability) {
	permitted := allowLanPermitted.Load()
	log.Infoln("[Apple] allow-lan permitted=%v", permitted)
	if !permitted {
		raw.AllowLan = false
	}
	raw.RedirPort = 0
	raw.TProxyPort = 0

	for _, knob := range strippedHostRouteKnobs(raw) {
		log.Warnln("[Apple NetworkExtension] %s has no Network Extension equivalent and is stripped; the config still starts", knob)
	}
	raw.Interface = ""
	raw.RoutingMark = 0
	if !capability.processPath {
		raw.FindProcessMode = process.FindProcessOff
	}
	raw.Tun.AutoRedirect = false
	raw.Tun.IPRoute2TableIndex = 0
	raw.Tun.IPRoute2RuleIndex = 0
	raw.Tun.AutoRedirectInputMark = 0
	raw.Tun.AutoRedirectOutputMark = 0
	raw.Tun.AutoRedirectIPRoute2FallbackRuleIndex = 0
	raw.Tun.IncludeInterface = nil
	raw.Tun.ExcludeInterface = nil
	raw.Tun.IncludeUID = nil
	raw.Tun.IncludeUIDRange = nil
	raw.Tun.ExcludeUID = nil
	raw.Tun.ExcludeUIDRange = nil
	raw.Tun.ExcludeSrcPort = nil
	raw.Tun.ExcludeSrcPortRange = nil
	raw.Tun.ExcludeDstPort = nil
	raw.Tun.ExcludeDstPortRange = nil
	raw.Tun.IncludeAndroidUser = nil
	raw.Tun.IncludePackage = nil
	raw.Tun.ExcludePackage = nil
	raw.Tun.IncludeMACAddress = nil
	raw.Tun.ExcludeMACAddress = nil

	raw.ExternalControllerRoutingMark = 0
	raw.ExternalControllerPipe = ""

	raw.IPTables.Enable = false
	raw.DNS.ListenRoutingMark = 0
	raw.NTP.WriteToSystem = false
}

func strippedHostRouteKnobs(raw *config.RawConfig) []string {
	knobs := make([]string, 0, 8)
	if raw.Interface != "" {
		knobs = append(knobs, "interface-name")
	}
	if raw.RoutingMark != 0 {
		knobs = append(knobs, "routing-mark")
	}
	tun := raw.Tun
	if tun.AutoRedirect {
		knobs = append(knobs, "tun.auto-redirect")
	}
	if tun.IPRoute2TableIndex != 0 || tun.IPRoute2RuleIndex != 0 ||
		tun.AutoRedirectInputMark != 0 || tun.AutoRedirectOutputMark != 0 ||
		tun.AutoRedirectIPRoute2FallbackRuleIndex != 0 {
		knobs = append(knobs, "tun.iproute2/auto-redirect marks")
	}
	if len(tun.IncludeInterface) > 0 || len(tun.ExcludeInterface) > 0 {
		knobs = append(knobs, "tun.include-interface/exclude-interface")
	}
	if len(tun.IncludeUID) > 0 || len(tun.IncludeUIDRange) > 0 ||
		len(tun.ExcludeUID) > 0 || len(tun.ExcludeUIDRange) > 0 {
		knobs = append(knobs, "tun.include-uid/exclude-uid")
	}
	if len(tun.IncludeAndroidUser) > 0 || len(tun.IncludePackage) > 0 || len(tun.ExcludePackage) > 0 {
		knobs = append(knobs, "tun.include-android-user/include-package/exclude-package")
	}
	if len(tun.IncludeMACAddress) > 0 || len(tun.ExcludeMACAddress) > 0 {
		knobs = append(knobs, "tun.include-mac-address/exclude-mac-address")
	}
	if len(tun.ExcludeSrcPort) > 0 || len(tun.ExcludeSrcPortRange) > 0 ||
		len(tun.ExcludeDstPort) > 0 || len(tun.ExcludeDstPortRange) > 0 {
		knobs = append(knobs, "tun.exclude-src-port/exclude-dst-port")
	}
	return knobs
}

func isNEIncompatibleNameserver(server string) bool {
	s := strings.ToLower(strings.TrimSpace(server))
	return s == "system" || strings.HasPrefix(s, "system:") || strings.HasPrefix(s, "dhcp:")
}

func isUsableBootstrapNameserver(server string) bool {
	s := strings.TrimSpace(server)
	if s == "" || isNEIncompatibleNameserver(s) {
		return false
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && net.ParseIP(u.Hostname()) != nil {
			return true
		}
		return false
	}
	host := s
	if h, _, err := net.SplitHostPort(s); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return net.ParseIP(host) != nil
}

func stripNEIncompatibleNameservers(raw *config.RawConfig) []string {
	stripped := []string{}
	filter := func(field string, list []string) []string {
		kept := make([]string, 0, len(list))
		for _, ns := range list {
			if isNEIncompatibleNameserver(ns) {
				stripped = append(stripped, field+" "+ns)
				continue
			}
			kept = append(kept, ns)
		}
		return kept
	}
	filterBootstrap := func(field string, list []string) []string {
		kept := make([]string, 0, len(list))
		var pending []string
		usable := false
		for _, ns := range list {
			if isNEIncompatibleNameserver(ns) {
				pending = append(pending, field+" "+ns)
				continue
			}
			kept = append(kept, ns)
			if isUsableBootstrapNameserver(ns) {
				usable = true
			}
		}
		if !usable {
			return list
		}
		stripped = append(stripped, pending...)
		return kept
	}
	raw.DNS.NameServer = filter("nameserver", raw.DNS.NameServer)
	raw.DNS.Fallback = filter("fallback", raw.DNS.Fallback)
	raw.DNS.ProxyServerNameserver = filter("proxy-server-nameserver", raw.DNS.ProxyServerNameserver)
	raw.DNS.DirectNameServer = filter("direct-nameserver", raw.DNS.DirectNameServer)
	raw.DNS.DefaultNameserver = filterBootstrap("default-nameserver", raw.DNS.DefaultNameserver)
	stripped = append(stripped, filterPolicyNameservers("nameserver-policy", raw.DNS.NameServerPolicy)...)
	stripped = append(stripped, filterPolicyNameservers("proxy-server-nameserver-policy", raw.DNS.ProxyServerNameserverPolicy)...)
	return stripped
}

func isDHCPNameserver(server string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(server)), "dhcp:")
}

func repairApplePacketTunnelDNS(raw *config.RawConfig) []string {
	repairs := []string{}
	defaults := config.DefaultRawConfig().DNS

	bootstrap := make([]string, 0, len(raw.DNS.DefaultNameserver))
	for _, server := range raw.DNS.DefaultNameserver {
		if isNEIncompatibleNameserver(server) {
			repairs = append(repairs, "default-nameserver system/dhcp bootstrap was replaced with explicit core bootstrap resolvers")
			continue
		}
		bootstrap = append(bootstrap, server)
	}
	if len(bootstrap) == 0 {
		bootstrap = append([]string(nil), defaults.DefaultNameserver...)
		if len(raw.DNS.DefaultNameserver) == 0 {
			repairs = append(repairs, "default-nameserver was empty and received explicit core bootstrap resolvers")
		}
	}
	raw.DNS.DefaultNameserver = bootstrap

	if !raw.DNS.Enable {
		raw.DNS.Enable = true
		repairs = append(repairs, "was enabled because an Apple packet tunnel always captures "+
			"port 53: with dns.enable false the core serves no DNS and every hijacked query "+
			"answers SERVFAIL, so the tunnel would start and resolve nothing")
	}
	if len(raw.DNS.NameServer) == 0 {
		raw.DNS.NameServer = append([]string(nil), defaults.NameServer...)
		repairs = append(repairs, "nameserver was empty after Apple normalization and received mihomo's explicit core defaults")
	}
	if raw.DNS.RespectRules && len(raw.DNS.ProxyServerNameserver) == 0 {
		raw.DNS.ProxyServerNameserver = append([]string(nil), bootstrap...)
		repairs = append(repairs, "proxy-server-nameserver was empty with respect-rules and received explicit bootstrap resolvers")
	}
	if raw.DNS.ProxyServerNameserverPolicy != nil && raw.DNS.ProxyServerNameserverPolicy.Oldest() != nil && len(raw.DNS.ProxyServerNameserver) == 0 {
		raw.DNS.ProxyServerNameserver = append([]string(nil), bootstrap...)
		repairs = append(repairs, "proxy-server-nameserver was empty with a policy and received explicit bootstrap resolvers")
	}
	return repairs
}

func filterPolicyNameservers(field string, policy *orderedmap.OrderedMap[string, any]) []string {
	if policy == nil {
		return nil
	}
	stripped := []string{}
	type policyEdit struct {
		key    string
		value  any
		remove bool
	}
	edits := []policyEdit{}
	for pair := policy.Oldest(); pair != nil; pair = pair.Next() {
		servers := dnsServerStrings(pair.Value)
		if len(servers) == 0 {
			continue
		}
		kept := make([]any, 0, len(servers))
		removed := false
		for _, ns := range servers {
			if isNEIncompatibleNameserver(ns) {
				stripped = append(stripped, field+" "+pair.Key+" "+ns)
				removed = true
				continue
			}
			kept = append(kept, ns)
		}
		if !removed {
			continue
		}
		if len(kept) == 0 {
			edits = append(edits, policyEdit{key: pair.Key, value: []any{"rcode://name_error"}})
		} else {
			edits = append(edits, policyEdit{key: pair.Key, value: kept})
		}
	}
	for _, edit := range edits {
		if edit.remove {
			policy.Delete(edit.key)
		} else {
			policy.Set(edit.key, edit.value)
		}
	}
	return stripped
}

func knownDNSFragmentProxies(raw *config.RawConfig) map[string]struct{} {
	known := map[string]struct{}{
		"DIRECT": {}, "REJECT": {}, "REJECT-DROP": {}, "COMPATIBLE": {},
		"PASS": {}, "PASS-RULE": {}, "GLOBAL": {}, dns.RespectRules: {},
	}
	for _, proxy := range raw.Proxy {
		if name, _ := proxy["name"].(string); name != "" {
			known[name] = struct{}{}
		}
	}
	for _, group := range raw.ProxyGroup {
		if name, _ := group["name"].(string); name != "" {
			known[name] = struct{}{}
		}
	}
	return known
}

func stripDNSFragmentName(server string) string {
	base, fragment, found := strings.Cut(server, "#")
	if !found {
		return server
	}
	kept := []string{}
	for _, component := range strings.Split(fragment, "&") {
		if strings.Contains(component, "=") {
			kept = append(kept, component)
		}
	}
	if len(kept) == 0 {
		return base
	}
	return base + "#" + strings.Join(kept, "&")
}

func detectUnroutableDNSFragments(raw *config.RawConfig) []string {
	known := knownDNSFragmentProxies(raw)
	stripped := []string{}
	rewrite := func(field string, list []string) {
		for index, server := range list {
			name := dnsFragmentProxyName(server)
			if name == "" {
				continue
			}
			if _, ok := known[name]; ok {
				continue
			}
			stripped = append(stripped, field+" "+server)
			_ = index
		}
	}
	rewrite("nameserver", raw.DNS.NameServer)
	rewrite("fallback", raw.DNS.Fallback)
	rewrite("default-nameserver", raw.DNS.DefaultNameserver)
	rewrite("proxy-server-nameserver", raw.DNS.ProxyServerNameserver)
	rewrite("direct-nameserver", raw.DNS.DirectNameServer)
	for field, policy := range map[string]*orderedmap.OrderedMap[string, any]{
		"nameserver-policy":              raw.DNS.NameServerPolicy,
		"proxy-server-nameserver-policy": raw.DNS.ProxyServerNameserverPolicy,
	} {
		if policy == nil {
			continue
		}
		for pair := policy.Oldest(); pair != nil; pair = pair.Next() {
			for _, server := range dnsServerStrings(pair.Value) {
				name := dnsFragmentProxyName(server)
				if name == "" {
					continue
				}
				if _, ok := known[name]; ok {
					continue
				}
				stripped = append(stripped, field+" "+pair.Key+" "+server)
			}
		}
	}
	return stripped
}

func stripOutboundEgressOverrides(raw *config.RawConfig) []string {
	stripped := []string{}
	forEachOutboundMapping(raw, func(location string, mapping map[string]any) {
		for _, key := range []string{"interface-name", "routing-mark"} {
			if value, exists := mapping[key]; exists && !isZeroish(value) {
				delete(mapping, key)
				stripped = append(stripped, location+"."+key)
			}
		}
	})
	return stripped
}

func validateRawConfigForIOS(raw *config.RawConfig) error {
	if err := validateRawProxyGroupRegexForIOS(raw.ProxyGroup); err != nil {
		return err
	}
	if err := validateRawProvidersForIOS("proxy-provider", raw.ProxyProvider); err != nil {
		return err
	}
	if err := validateRawProvidersForIOS("rule-provider", raw.RuleProvider); err != nil {
		return err
	}
	return validateGeodataFilesForIOS(raw)
}

func validateRawProxyGroupRegexForIOS(groups []map[string]any) error {
	for index, group := range groups {
		for _, field := range []string{"filter", "exclude-filter"} {
			value, ok := group[field].(string)
			if !ok || value == "" {
				continue
			}
			for _, expression := range strings.Split(value, "`") {
				if _, err := regexp2.Compile(expression, regexp2.None); err != nil {
					return fmt.Errorf("hako: proxy-groups[%d].%s is not a valid regular expression", index, field)
				}
			}
		}
	}
	return nil
}

func validateRawProvidersForIOS(kind string, providers map[string]map[string]any) error {
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		provider := providers[name]
		if kind == "proxy-provider" {
			if err := validateProxyProviderHealthCheck(name, provider); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateProxyProviderHealthCheck(name string, provider map[string]any) error {
	raw, exists := provider["health-check"]
	if !exists {
		return nil
	}
	healthCheck, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	fields := []struct {
		name      string
		unit      time.Duration
		unitLabel string
	}{
		{name: "interval", unit: time.Second, unitLabel: "second"},
	}
	for _, field := range fields {
		if _, err := providerDurationUnits(healthCheck[field.name], field.unit, "health-check "+field.name, field.unitLabel); err != nil {
			return fmt.Errorf("hako: proxy-provider %q health-check.%s: %w", name, field.name, err)
		}
	}
	return nil
}

type geodataRequirements struct {
	geoIP   bool
	geoSite bool
	asn     bool
}

var geodataRuleToken = regexp.MustCompile(`(?i)(?:^|\()\s*(GEOIP|SRC-GEOIP|GEOSITE|IP-ASN|SRC-IP-ASN)\s*,\s*([^,()]*)`)

func validateGeodataFilesForIOS(raw *config.RawConfig) error {
	required := requiredGeodata(raw)
	if required.geoIP {
		path := C.Path.MMDB()
		if raw.GeodataMode {
			path = C.Path.GeoIP()
		}
		if err := requirePrestagedFile("GeoIP", path); err != nil {
			return err
		}
	}
	if required.geoSite {
		if err := requirePrestagedFile("GeoSite", C.Path.GeoSite()); err != nil {
			return err
		}
		geodata.MarkGeoSiteVerified()
	}
	if required.asn {
		if err := requirePrestagedFile("ASN", C.Path.ASN()); err != nil {
			return err
		}
	}
	return nil
}

func requirePrestagedFile(kind, path string) error {
	if path == "" {
		return fmt.Errorf("hako: %s geodata path is unavailable; call Setup before Start", kind)
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("hako: required %s geodata is not pre-staged at %s (NE downloads are disabled)", kind, path)
		}
		return fmt.Errorf("hako: stat %s geodata at %s: %w", kind, path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("hako: required %s geodata at %s is not a regular file", kind, path)
	}
	return nil
}

func requiredGeodata(raw *config.RawConfig) geodataRequirements {
	var required geodataRequirements
	for _, line := range raw.Rule {
		markRuleGeodata(line, &required)
	}
	for _, rules := range raw.SubRules {
		for _, line := range rules {
			markRuleGeodata(line, &required)
		}
	}
	for _, line := range raw.DNS.FakeIPFilter {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "geosite:") {
			required.geoSite = true
		} else {
			markRuleGeodata(line, &required)
		}
	}
	if len(raw.DNS.Fallback) > 0 {
		required.geoIP = required.geoIP || raw.DNS.FallbackFilter.GeoIP
		required.geoSite = required.geoSite || len(raw.DNS.FallbackFilter.GeoSite) > 0
	}
	markPolicyGeosite(raw.DNS.NameServerPolicy, &required)
	markPolicyGeosite(raw.DNS.ProxyServerNameserverPolicy, &required)
	return required
}

func markRuleGeodata(line string, required *geodataRequirements) {
	for _, match := range geodataRuleToken.FindAllStringSubmatch(line, -1) {
		switch strings.ToUpper(match[1]) {
		case "GEOIP", "SRC-GEOIP":
			if strings.ToLower(strings.TrimSpace(match[2])) != "lan" {
				required.geoIP = true
			}
		case "GEOSITE":
			required.geoSite = true
		case "IP-ASN", "SRC-IP-ASN":
			required.asn = true
		}
	}
}

func markPolicyGeosite(policy *orderedmap.OrderedMap[string, any], required *geodataRequirements) {
	if policy == nil {
		return
	}
	for pair := policy.Oldest(); pair != nil; pair = pair.Next() {
		if strings.HasPrefix(strings.ToLower(pair.Key), "geosite:") {
			required.geoSite = true
		}
	}
}
