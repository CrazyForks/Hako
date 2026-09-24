package hako

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/TokenPLS/Hako/adapter/outboundgroup"
	"github.com/TokenPLS/Hako/component/geodata"
	"github.com/TokenPLS/Hako/config"
	C "github.com/TokenPLS/Hako/constant"
	P "github.com/TokenPLS/Hako/constant/provider"
	"go.yaml.in/yaml/v3"
)

type detachedLoader interface {
	LoadDetached(buf []byte, updatedAt time.Time) error
}

var catalogIgnoredSections = []string{
	"rules", "sub-rules", "rule-providers", "dns", "hosts", "sniffer",
	"tun", "listeners", "tunnels", "ntp", "experimental",
}

func ProxyCatalogForIOS(configContent, resourceMapJSON, selectionsJSON string) (*StringBox, error) {
	catalog, err := proxyCatalogRecovering(configContent, resourceMapJSON, selectionsJSON)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return catalog, nil
}

func proxyCatalogRecovering(configContent, resourceMapJSON, selectionsJSON string) (catalog *StringBox, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			catalog, err = nil, fmt.Errorf("hako: proxy catalog: %v", recovered)
		}
	}()
	return proxyCatalog(configContent, resourceMapJSON, selectionsJSON)
}

func proxyCatalog(configContent, resourceMapJSON, selectionsJSON string) (*StringBox, error) {
	setupMu.Lock()
	ready := setupDone
	setupMu.Unlock()
	if !ready {
		return nil, bridgeSafeError(fmt.Errorf("hako: call Setup before ProxyCatalogForIOS"))
	}
	var resources resourceMap
	if resourceMapJSON != "" {
		if err := json.Unmarshal([]byte(resourceMapJSON), &resources); err != nil {
			return nil, bridgeSafeError(fmt.Errorf("hako: resource map: %w", err))
		}
	}
	selections := map[string]string{}
	if selectionsJSON != "" {
		if err := json.Unmarshal([]byte(selectionsJSON), &selections); err != nil {
			return nil, bridgeSafeError(fmt.Errorf("hako: selections: %w", err))
		}
	}
	document, staged, err := catalogDocument(configContent, resources)
	if err != nil {
		return nil, bridgeSafeError(err)
	}

	appParseMu.Lock()
	defer appParseMu.Unlock()
	previousGeoSiteOnly, previousGeoIPOnly := geodata.CompiledGeoSiteOnly(), geodata.CompiledGeoIPOnly()
	defer func() {
		geodata.SetCompiledGeoSiteOnly(previousGeoSiteOnly)
		geodata.SetCompiledGeoIPOnly(previousGeoIPOnly)
	}()

	cfg, err := parseConfigForIOS(document, true)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	defer closeCatalogObjects(cfg.Proxies, cfg.Providers)

	providerErrors := map[string]string{}
	for name, provider := range cfg.Providers {
		loader, ok := provider.(detachedLoader)
		if !ok {
			continue
		}
		vehicle, ok := provider.(interface{ Vehicle() P.Vehicle })
		if !ok {
			continue
		}
		path := vehicle.Vehicle().Path()
		info, err := os.Stat(path)
		if err != nil {
			if !os.IsNotExist(err) {
				providerErrors[name] = err.Error()
			}
			continue
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			providerErrors[name] = err.Error()
			continue
		}
		content := payload
		if format, ok := staged[name]; ok {
			content = proxyProviderRuntimeContent(format, payload)
		}
		if err := loader.LoadDetached(content, info.ModTime()); err != nil {
			providerErrors[name] = err.Error()
		}
	}

	restoreCatalogSelections(cfg, selections)

	data, err := json.Marshal(map[string]any{
		"proxies":        cfg.Proxies,
		"providers":      cfg.Providers,
		"providerErrors": providerErrors,
	})
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: encode proxy catalog: %w", err))
	}
	return WrapString(bridgeSafeString(string(data))), nil
}

func catalogDocument(content string, resources resourceMap) (string, map[string]string, error) {
	var root map[string]any
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		return "", nil, fmt.Errorf("hako: parse config: %w", err)
	}
	if root == nil {
		root = map[string]any{}
	}
	canonicalizeProviderDefinitionKeysInDocument(root)
	collisions := providerNamespaceCollisions(root)
	if err := rewriteProviders(root, "proxy-providers", "proxy", resources.ProviderPaths, collisions); err != nil {
		return "", nil, err
	}
	staged := map[string]string{}
	if providers, ok := root["proxy-providers"].(map[string]any); ok {
		for name, raw := range providers {
			definition, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if kind, _ := definition["type"].(string); strings.EqualFold(kind, "file") {
				staged[name], _ = definition["format"].(string)
			}
		}
	}
	for _, key := range catalogIgnoredSections {
		delete(root, key)
	}
	out, err := yaml.Marshal(root)
	if err != nil {
		return "", nil, fmt.Errorf("hako: encode catalog document: %w", err)
	}
	return string(out), staged, nil
}

func proxyProviderRuntimeContent(format string, payload []byte) []byte {
	prepared, stripped, err := sanitizeProxyProviderPayloadForIOS(format, payload, false)
	if err == nil && len(stripped) > 0 {
		return prepared
	}
	return payload
}

func restoreCatalogSelections(cfg *config.Config, selections map[string]string) {
	for group, member := range selections {
		proxy, ok := cfg.Proxies[group]
		if !ok {
			continue
		}
		selectable, ok := proxy.Adapter().(outboundgroup.SelectAble)
		if !ok {
			continue
		}
		if cfg.Profile.StoreSelected || groupHasMember(proxy, member) {
			selectable.ForceSet(member)
		}
	}
}

func groupHasMember(group C.Proxy, member string) bool {
	holder, ok := group.Adapter().(interface{ GetProxies(bool) []C.Proxy })
	if !ok {
		return false
	}
	for _, proxy := range holder.GetProxies(false) {
		if proxy.Name() == member {
			return true
		}
	}
	return false
}

func closeCatalogObjects(proxies map[string]C.Proxy, providers map[string]P.ProxyProvider) {
	for _, proxy := range proxies {
		if closer, ok := proxy.Adapter().(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}
	for _, provider := range providers {
		if closer, ok := provider.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}
}
