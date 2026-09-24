package hako

import (
	"fmt"

	"github.com/TokenPLS/Hako/config"
	"github.com/TokenPLS/Hako/log"
)

func StageProvidersForPublish(configContent string, targetProfile string, compileRuleSets bool) error {
	appParseMu.Lock()
	defer appParseMu.Unlock()
	profile, err := normalizeRuntimeProfile(targetProfile)
	if err != nil {
		return bridgeSafeError(err)
	}
	raw, err := config.UnmarshalRawConfig([]byte(configContent))
	if err != nil {
		return bridgeSafeError(fmt.Errorf("hako: parse config: %w", err))
	}
	canonicalizeProviderDefinitionKeys(raw)
	policy := runtimePolicyFor(profile, true)
	normalizeRawConfigForApple(raw, policy)
	runtime, err := stageProviderRuntime(raw, policy, compileRuleSets)
	if err != nil {
		return bridgeSafeError(err)
	}
	verdicts := providerVerdictCounts{}
	if runtime != nil {
		verdicts = runtime.verdicts
		runtime.close()
	}
	log.Infoln("[Apple] provider publish staged into %s: compiled=%d notCompilable=%d keptSource=%d",
		stagedProviderParentDirectory(), verdicts.compiled, verdicts.notCompilable, verdicts.keptSource)
	return nil
}

func DiscardPublishedProviderStaging() {
	parent := stagedProviderParentDirectory()
	manifest := &stagedProviderManifest{Entries: map[string]stagedProviderRecord{}}
	saveStagedProviderManifest(parent, manifest)
	sweepStagedProviderRuntime(parent, stagedProviderDirectory(), map[string]struct{}{})
	log.Infoln("[Apple] published provider staging discarded; the next start will stage from source")
}
