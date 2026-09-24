package hako

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

func ConfigDeviationsJSON(configContent string, targetProfile string) (*StringBox, error) {
	profile, err := normalizeRuntimeProfile(targetProfile)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	deviations, err := collectConfigDeviations(configContent, runtimePolicyFor(profile, true))
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: collect config deviations: %w", err))
	}
	sum := sha256.Sum256([]byte(configContent))
	payload := struct {
		SchemaVersion int                       `json:"schemaVersion"`
		Document      deviationDocumentIdentity `json:"document"`
		Deviations    []configDeviation         `json:"deviations"`
	}{configDeviationSchemaVersion, deviationDocumentIdentity{Bytes: len(configContent), SHA256: hex.EncodeToString(sum[:])}, deviations}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: encode config deviations: %w", err))
	}
	return WrapString(string(encoded)), nil
}
