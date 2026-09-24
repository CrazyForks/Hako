package tunnel

import (
	P "github.com/TokenPLS/Hako/constant/provider"
	"maps"
)

func SnapshotRuleProviders() map[string]P.RuleProvider {
	configMux.RLock()
	defer configMux.RUnlock()
	return maps.Clone(ruleProviders)
}
