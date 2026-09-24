package hako

import (
	"encoding/json"
	"fmt"
	"runtime"
	"sync/atomic"

	"github.com/TokenPLS/Hako/config"
	"gopkg.in/yaml.v3"
)

type documentViews struct {
	rawText string
	root    map[string]any
	raw     *config.RawConfig
}

type ConfigDocument struct {
	views atomic.Pointer[documentViews]
}

func NewConfigDocument(configContent string) (*ConfigDocument, error) {
	if err := validateConfigurationInput(configContent); err != nil {
		return nil, bridgeSafeError(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(configContent), &root); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: parse config: %w", err))
	}
	raw, err := config.UnmarshalRawConfig([]byte(configContent))
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: parse config: %w", err))
	}
	doc := &ConfigDocument{}
	doc.views.Store(&documentViews{rawText: configContent, root: root, raw: raw})
	runtime.SetFinalizer(doc, func(d *ConfigDocument) { d.Close() })
	return doc, nil
}

func (d *ConfigDocument) Close() {
	if d.views.Swap(nil) != nil {
		runtime.SetFinalizer(d, nil)
	}
}

func (d *ConfigDocument) snapshot() (*documentViews, error) {
	views := d.views.Load()
	if views == nil {
		return nil, fmt.Errorf("hako: config document is closed")
	}
	return views, nil
}

func (d *ConfigDocument) closedErr() error {
	_, err := d.snapshot()
	return err
}

func (d *ConfigDocument) ProjectionJSON(kind string, packagesJSON string) (*StringBox, error) {
	var packages []string
	if err := json.Unmarshal([]byte(packagesJSON), &packages); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: parse projection package list: %w", err))
	}
	if len(packages) == 0 {
		return nil, bridgeSafeError(fmt.Errorf("hako: projection requested with no packages"))
	}
	for _, name := range packages {
		switch name {
		case projectionPackageCatalog, projectionPackageResources,
			projectionPackageRuleFacts, projectionPackageScalars:
		default:
			return nil, bridgeSafeError(fmt.Errorf("hako: unknown projection package %q", name))
		}
	}
	projection, err := buildConfigProjection(d, kind, packages)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	payload, err := json.Marshal(projection)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	if err := validateConfigurationJSONResult(string(payload)); err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(string(payload)), nil
}
