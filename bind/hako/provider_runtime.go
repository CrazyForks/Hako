package hako

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/TokenPLS/Hako/config"
	C "github.com/TokenPLS/Hako/constant"
	P "github.com/TokenPLS/Hako/constant/provider"
	"github.com/TokenPLS/Hako/log"
	"github.com/TokenPLS/Hako/tunnel"
)

const providerRuntimeDirectoryName = "provider-runtime"
const providerSideUpdateSafeField = "x-hako-side-update-safe"

type providerRuntimeEntry struct {
	behavior       string
	format         string
	compiled       bool
	sideUpdateSafe bool
	runtimePath    string
}

type providerVerdictCounts struct {
	compiled      int
	notCompilable int
	keptSource    int
}

type providerRuntime struct {
	directory string
	entries   map[string]providerRuntimeEntry
	policy    appleRuntimePolicy
	verdicts  providerVerdictCounts
}

func providerRuntimeKey(kind, name string) string {
	return kind + "\x00" + name
}

type stagingCost struct {
	hitCount       int
	hitNanos       int64
	readCount      int
	readNanos      int64
	readBytes      int64
	mrsCount       int
	mrsNanos       int64
	classicalCount int
	classicalNanos int64
	proxyCount     int
	proxyNanos     int64
	commitCount    int
	commitNanos    int64
	compileCount   int
	compileNanos   int64
}

func (c *stagingCost) line() string {
	ms := func(n int64) float64 { return float64(n) / 1e6 }
	return fmt.Sprintf(
		"stage-cost hit=%d/%.0fms read=%d/%.0fms/%.1fMiB mrs=%d/%.0fms classical=%d/%.0fms proxy=%d/%.0fms commit=%d/%.0fms",
		c.hitCount, ms(c.hitNanos),
		c.readCount, ms(c.readNanos), float64(c.readBytes)/(1<<20),
		c.mrsCount, ms(c.mrsNanos),
		c.classicalCount, ms(c.classicalNanos),
		c.proxyCount, ms(c.proxyNanos),
		c.commitCount, ms(c.commitNanos)) + func() string {
		if c.compileCount == 0 {
			return ""
		}
		return fmt.Sprintf(" compile=%d/%.0fms", c.compileCount, ms(c.compileNanos))
	}()
}

const providerRuntimeStagedDirectoryName = "staged"

func stagedProviderParentDirectory() string {
	return filepath.Join(C.Path.HomeDir(), providerRuntimeDirectoryName)
}

func stagedProviderDirectory() string {
	return filepath.Join(stagedProviderParentDirectory(), providerRuntimeStagedDirectoryName)
}

const providerRuntimeManifestName = "staged-manifest.json"

const providerStagingLogicVersion = 6

type stagedProviderNoop struct {
	Kind   string `json:"kind,omitempty"`
	Field  string `json:"field,omitempty"`
	Index  int    `json:"index"`
	Reason int    `json:"reason,omitempty"`
}

type stagedProviderRecord struct {
	Source         string `json:"source"`
	SourceSize     int64  `json:"sourceSize"`
	SourceMtimeNS  int64  `json:"sourceMtimeNS"`
	SourceInode    uint64 `json:"sourceInode"`
	Behavior       string `json:"behavior,omitempty"`
	Format         string `json:"format,omitempty"`
	SideUpdateSafe bool   `json:"sideUpdateSafe,omitempty"`
	File           string `json:"file"`
	StagedSize     int64  `json:"stagedSize"`
	Count          int                  `json:"count,omitempty"`
	EgressNoops    []stagedProviderNoop `json:"egressNoops,omitempty"`
	MetadataNoops  []stagedProviderNoop `json:"metadataNoops,omitempty"`
	UnreadableWarn string               `json:"unreadableWarn,omitempty"`
	CompileVerdict   string `json:"compileVerdict,omitempty"`
	CompiledBehavior string `json:"compiledBehavior,omitempty"`
	CompileReason    string `json:"compileReason,omitempty"`
	ContentSHA256 string `json:"contentSHA256,omitempty"`
}

func compiledBehaviorIsKnown(behavior string) bool {
	switch behavior {
	case "domain", "ipcidr", "classical":
		return true
	default:
		return false
	}
}

const maximumStagedManifestBytes = 4 << 20

func stagedFileDigest(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func requireRealDirectoryOrAbsent(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !info.IsDir() {
		return errors.New("path exists and is not a directory")
	}
	return nil
}

const SideUpdateDeferredPrefix = "hako: side update deferred: "

const (
	compileVerdictCompiled      = "compiled"
	compileVerdictNotCompilable = "notCompilable"
	compileVerdictKeptSource    = "keptSource"
)

type stagedProviderManifest struct {
	Schema  int                             `json:"schema"`
	Logic   int                             `json:"logic"`
	Core    string                          `json:"core"`
	Policy  string                          `json:"policy"`
	Entries map[string]stagedProviderRecord `json:"entries"`
}

func stagedPolicyFingerprint(policy appleRuntimePolicy) string {
	return fmt.Sprintf("%+v", policy)
}

func newStagedProviderManifest(policy appleRuntimePolicy) *stagedProviderManifest {
	return &stagedProviderManifest{
		Schema:  1,
		Logic:   providerStagingLogicVersion,
		Core:    C.Version,
		Policy:  stagedPolicyFingerprint(policy),
		Entries: map[string]stagedProviderRecord{},
	}
}

func loadStagedProviderManifest(parent string, policy appleRuntimePolicy) *stagedProviderManifest {
	empty := &stagedProviderManifest{Entries: map[string]stagedProviderRecord{}}
	payload, err := readBoundedRegularFile(
		filepath.Join(parent, providerRuntimeManifestName),
		maximumStagedManifestBytes, "provider staging manifest")
	if err != nil {
		return empty
	}
	manifest := &stagedProviderManifest{}
	if json.Unmarshal(payload, manifest) != nil || manifest.Entries == nil {
		return empty
	}
	if manifest.Schema != 1 ||
		manifest.Logic != providerStagingLogicVersion ||
		manifest.Core != C.Version ||
		manifest.Policy != stagedPolicyFingerprint(policy) {
		return empty
	}
	return manifest
}

func saveStagedProviderManifest(parent string, manifest *stagedProviderManifest) {
	payload, err := json.Marshal(manifest)
	if err == nil {
		err = writeRuntimeProviderFile(
			filepath.Join(parent, providerRuntimeManifestName), payload)
	}
	if err != nil {
		log.Warnln("[Apple] provider staging manifest not recorded (%v); the next start restages from source", err)
	}
}

type providerSourceIdentity struct {
	size    int64
	mtimeNS int64
	inode   uint64
}

func stagedSourceIdentity(path string) (providerSourceIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return providerSourceIdentity{}, err
	}
	if !info.Mode().IsRegular() {
		return providerSourceIdentity{}, errors.New("published provider is not a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return providerSourceIdentity{}, errors.New("published provider carries no inode identity")
	}
	return providerSourceIdentity{
		size:    info.Size(),
		mtimeNS: info.ModTime().UnixNano(),
		inode:   stat.Ino,
	}, nil
}

func stagedProviderRecordMatches(record stagedProviderRecord, sourcePath, behavior, format string) bool {
	if record.Source != sourcePath || record.Behavior != behavior || record.Format != format {
		return false
	}
	identity, err := stagedSourceIdentity(sourcePath)
	if err != nil {
		return false
	}
	return identity.size == record.SourceSize &&
		identity.mtimeNS == record.SourceMtimeNS &&
		identity.inode == record.SourceInode
}

func stagedFileMatches(path string, record stagedProviderRecord) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != record.StagedSize {
		return false
	}
	if record.ContentSHA256 == "" {
		return false
	}
	if record.StagedSize < 0 || record.StagedSize > int64(maximumProviderResourceBytes) {
		return false
	}
	payload, err := os.ReadFile(path)
	if err != nil || int64(len(payload)) != record.StagedSize {
		return false
	}
	return stagedFileDigest(payload) == record.ContentSHA256
}

func replayStagedProviderWarnings(name, kind string, record stagedProviderRecord) {
	if record.UnreadableWarn != "" {
		if kind == "proxy" {
			warnUnreadableProxyProvider(name, errors.New(record.UnreadableWarn))
		} else {
			warnUnreadableRuleProvider(name, errors.New(record.UnreadableWarn))
		}
	}
	if len(record.EgressNoops) > 0 {
		stripped := make([]providerEgressNoop, 0, len(record.EgressNoops))
		for _, noop := range record.EgressNoops {
			stripped = append(stripped, providerEgressNoop{field: noop.Field, index: noop.Index})
		}
		warnProviderEgressNoops(name, stripped)
	}
	if len(record.MetadataNoops) > 0 {
		stripped := make([]providerMetadataNoop, 0, len(record.MetadataNoops))
		for _, noop := range record.MetadataNoops {
			stripped = append(stripped, providerMetadataNoop{
				kind: noop.Kind, index: noop.Index,
				reason: providerNoopReason(noop.Reason),
			})
		}
		warnProviderMetadataNoops(name, stripped)
	}
}

func encodeEgressNoops(stripped []providerEgressNoop) []stagedProviderNoop {
	if len(stripped) == 0 {
		return nil
	}
	encoded := make([]stagedProviderNoop, 0, len(stripped))
	for _, noop := range stripped {
		encoded = append(encoded, stagedProviderNoop{Field: noop.field, Index: noop.index})
	}
	return encoded
}

func encodeMetadataNoops(stripped []providerMetadataNoop) []stagedProviderNoop {
	if len(stripped) == 0 {
		return nil
	}
	encoded := make([]stagedProviderNoop, 0, len(stripped))
	for _, noop := range stripped {
		encoded = append(encoded, stagedProviderNoop{
			Kind: noop.kind, Index: noop.index, Reason: int(noop.reason),
		})
	}
	return encoded
}

func invalidateStagedProviderRecord(kind, name string) {
	parent := filepath.Join(C.Path.HomeDir(), providerRuntimeDirectoryName)
	payload, err := readBoundedRegularFile(
		filepath.Join(parent, providerRuntimeManifestName),
		maximumStagedManifestBytes, "provider staging manifest")
	if err != nil {
		return
	}
	manifest := &stagedProviderManifest{}
	if json.Unmarshal(payload, manifest) != nil || manifest.Entries == nil {
		return
	}
	key := providerRuntimeKey(kind, name)
	if _, exists := manifest.Entries[key]; !exists {
		return
	}
	delete(manifest.Entries, key)
	saveStagedProviderManifest(parent, manifest)
}

func sweepStagedProviderRuntime(parent, stagedDirectory string, referenced map[string]struct{}) {
	if entries, err := os.ReadDir(parent); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if name == providerRuntimeStagedDirectoryName || name == providerRuntimeManifestName {
				continue
			}
			_ = os.RemoveAll(filepath.Join(parent, name))
		}
	}
	files, err := os.ReadDir(stagedDirectory)
	if err != nil {
		return
	}
	for _, file := range files {
		if _, keep := referenced[file.Name()]; keep {
			continue
		}
		if _, keep := referenced[strings.TrimSuffix(file.Name(), providerRuntimeCompiledSuffix)]; keep {
			continue
		}
		if _, keep := referenced[file.Name()+providerRuntimeCompiledSuffix]; keep {
			continue
		}
		_ = os.Remove(filepath.Join(stagedDirectory, file.Name()))
	}
}

func stageProviderRuntime(raw *config.RawConfig, policy appleRuntimePolicy, compileRuleSets bool) (*providerRuntime, error) {
	definitions := []struct {
		kind      string
		providers map[string]map[string]any
	}{{kind: "proxy", providers: raw.ProxyProvider}, {kind: "rule", providers: raw.RuleProvider}}

	parent := filepath.Join(C.Path.HomeDir(), providerRuntimeDirectoryName)
	stagedDirectory := filepath.Join(parent, providerRuntimeStagedDirectoryName)
	var runtime *providerRuntime
	var manifest, next *stagedProviderManifest
	referenced := map[string]struct{}{}
	var cost stagingCost
	cleanupOnError := func(err error) (*providerRuntime, error) {
		if runtime != nil {
			runtime.close()
		}
		return nil, err
	}
	for _, namespace := range definitions {
		names := make([]string, 0, len(namespace.providers))
		for name := range namespace.providers {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			definition := namespace.providers[name]
			typeName, _ := definition["type"].(string)
			if typeName != "file" {
				continue
			}
			sourceValue, _ := definition["path"].(string)
			if strings.TrimSpace(sourceValue) == "" {
				return cleanupOnError(fmt.Errorf("hako: %s provider path is empty", namespace.kind))
			}
			sourcePath := C.Path.Resolve(sourceValue)
			if pathInsideDirectory(sourcePath, parent) {
				return cleanupOnError(fmt.Errorf("hako: %s provider source points into runtime storage", namespace.kind))
			}
			if !providerSourceContained(sourcePath, C.Path.HomeDir()) {
				return cleanupOnError(fmt.Errorf(
					"hako: %s provider %q names a path outside this app's container and cannot be read",
					namespace.kind, name))
			}
			if runtime == nil {
				if err := requireRealDirectoryOrAbsent(parent); err != nil {
					return nil, fmt.Errorf("hako: provider runtime directory: %w", err)
				}
				if err := os.MkdirAll(stagedDirectory, 0o700); err != nil {
					return nil, fmt.Errorf("hako: create provider runtime directory: %w", err)
				}
				if err := requireRealDirectoryOrAbsent(stagedDirectory); err != nil {
					return nil, fmt.Errorf("hako: provider runtime directory: %w", err)
				}
				if err := os.Chmod(stagedDirectory, 0o700); err != nil {
					return nil, fmt.Errorf("hako: protect provider runtime directory: %w", err)
				}
				runtime = &providerRuntime{
					directory: stagedDirectory,
					entries:   make(map[string]providerRuntimeEntry),
					policy:    policy,
				}
				manifest = loadStagedProviderManifest(parent, policy)
				next = newStagedProviderManifest(policy)
			}
			behavior, _ := definition["behavior"].(string)
			format, _ := definition["format"].(string)
			fileName := providerRuntimeFileName(namespace.kind, name)
			runtimePath := filepath.Join(stagedDirectory, fileName)
			key := providerRuntimeKey(namespace.kind, name)
			hitFileName, hitRuntimePath := fileName, runtimePath
			if record, hit := manifest.Entries[key]; hit &&
				record.File == providerRuntimeCompiledFileName(namespace.kind, name) {
				hitFileName = record.File
				hitRuntimePath = filepath.Join(stagedDirectory, hitFileName)
			}
			sideUpdateSafe := namespace.kind == "proxy"
			if namespace.kind == "rule" {
				sideUpdateSafe, _ = definition[providerSideUpdateSafeField].(bool)
			}

			hitStart := time.Now()
			if record, hit := manifest.Entries[key]; hit &&
				stagedProviderRecordMatches(record, sourcePath, behavior, format) &&
				stagedFileMatches(hitRuntimePath, record) &&
				!(compileRuleSets && namespace.kind == "rule" &&
					record.CompileVerdict == "" && record.UnreadableWarn == "") {
				cost.hitCount++
				cost.hitNanos += time.Since(hitStart).Nanoseconds()
				if namespace.kind == "rule" {
					logRuleProviderDisposition(name, record)
				}
				replayStagedProviderWarnings(name, namespace.kind, record)
				record.SideUpdateSafe = sideUpdateSafe
				entryBehavior, entryFormat := behavior, format
				if record.CompileVerdict == compileVerdictCompiled &&
					!compiledBehaviorIsKnown(record.CompiledBehavior) {
					log.Warnln("[Apple] staged rule provider %q records an unknown compiled behavior; restaging from source", name)
					record = stagedProviderRecord{}
				}
				if record.CompileVerdict == compileVerdictCompiled {
					definition["format"] = "mrs"
					definition["behavior"] = record.CompiledBehavior
					entryBehavior, entryFormat = record.CompiledBehavior, "mrs"
				}
				next.Entries[key] = record
				referenced[hitFileName] = struct{}{}
				runtime.entries[key] = providerRuntimeEntry{
					behavior: entryBehavior, format: entryFormat, sideUpdateSafe: sideUpdateSafe,
					compiled:    record.CompileVerdict == compileVerdictCompiled && record.Format != "mrs",
					runtimePath: hitRuntimePath,
				}
				definition["path"] = hitRuntimePath
				continue
			}

			identity, err := stagedSourceIdentity(sourcePath)
			if err != nil {
				log.Warnln("[Apple] %s provider %q could not be staged (%v); it rides empty and the configuration still starts, as it does upstream",
					namespace.kind, name, err)
				continue
			}
			record := stagedProviderRecord{
				Source:     sourcePath,
				SourceSize: identity.size, SourceMtimeNS: identity.mtimeNS, SourceInode: identity.inode,
				Behavior: behavior, Format: format, SideUpdateSafe: sideUpdateSafe,
				File: fileName,
			}
			commitStart := time.Now()
			if namespace.kind == "rule" {
				if err := ruleProviderSchemaError(behavior, format); err != nil {
					return cleanupOnError(fmt.Errorf("hako: stage rule provider runtime: %w", err))
				}
				readStart := time.Now()
				var payload []byte
				if identity.size > 0 {
					payload, err = readBoundedRegularFile(sourcePath, int64(maximumProviderResourceBytes), "published provider")
				}
				cost.readCount++
				cost.readNanos += time.Since(readStart).Nanoseconds()
				cost.readBytes += int64(len(payload))
				if err != nil {
					return cleanupOnError(fmt.Errorf("hako: stage rule provider runtime: %w", err))
				}
				prepareStart := time.Now()
				prepared, stripped, prepareErr := prepareRuleProviderRuntimePayload(behavior, format, payload, policy)
				if strings.EqualFold(strings.TrimSpace(format), "mrs") {
					cost.mrsCount++
					cost.mrsNanos += time.Since(prepareStart).Nanoseconds()
				} else {
					cost.classicalCount++
					cost.classicalNanos += time.Since(prepareStart).Nanoseconds()
				}
				if compileRuleSets && prepareErr == nil &&
					strings.EqualFold(strings.TrimSpace(format), "mrs") {
					record.CompileVerdict = compileVerdictCompiled
					record.CompiledBehavior = strings.ToLower(strings.TrimSpace(behavior))
				}
				if compileRuleSets && prepareErr == nil && identity.size > 0 &&
					!strings.EqualFold(strings.TrimSpace(format), "mrs") {
					content := payload
					if len(stripped) > 0 {
						content = prepared
					}
					compileStart := time.Now()
					compilation := compileRuleProviderPayload(content, behavior, format)
					cost.compileCount++
					cost.compileNanos += time.Since(compileStart).Nanoseconds()
					if compilation.Reason != "" {
						if len(stripped) > 0 {
							if err := writeRuntimeProviderFile(runtimePath, prepared); err != nil {
								return cleanupOnError(fmt.Errorf("hako: stage rule provider runtime: %w", err))
							}
							record.MetadataNoops = encodeMetadataNoops(stripped)
							warnProviderMetadataNoops(name, stripped)
						} else if err := stageRuntimeProviderFile(sourcePath, runtimePath); err != nil {
							return cleanupOnError(fmt.Errorf("hako: stage rule provider runtime: %w", err))
						}
						record.CompileVerdict = compileVerdictKeptSource
						record.CompileReason = compilation.Reason
						logKeptSourceRuleProvider(name, compilation.Reason)
					} else {
						fileName = providerRuntimeCompiledFileName(namespace.kind, name)
						runtimePath = filepath.Join(stagedDirectory, fileName)
						record.File = fileName
						if err := writeRuntimeProviderFile(runtimePath, compilation.artifact); err != nil {
							return cleanupOnError(fmt.Errorf("hako: stage rule provider runtime: %w", err))
						}
						record.CompileVerdict = compileVerdictCompiled
						record.CompiledBehavior = compilation.Behavior
						definition["format"] = "mrs"
						definition["behavior"] = compilation.Behavior
						if len(stripped) > 0 {
							record.MetadataNoops = encodeMetadataNoops(stripped)
							warnProviderMetadataNoops(name, stripped)
						}
						log.Infoln("[Apple] rule provider %q compiled to MRS: %d rules, %d bytes",
							name, compilation.Rules, len(compilation.artifact))
					}
				} else {
					switch {
					case prepareErr != nil:
						// A rule set this core cannot read is not a reason to refuse the
						// configuration. Upstream loads providers with
						// hub/executor/executor.go:318-338, where a failed Initial() produces
						// `log.Errorln("initial rule provider %s error: %v")` and nothing
						// else -- the config starts and that one rule set is empty. Nor is
						// the failure platform-relevant: an unreadable rule set costs no
						// memory, spawns nothing, downloads nothing (it is already a staged
						// file provider) and leaves no sandbox. Both questions answer
						// no, so this may not be fatal.
						//
						// It was, and it cost a real user 26 working rule sets: an OpenClash
						// export with 27 rule providers had exactly one pointing at a GitHub
						// /blob/ HTML page while declaring format: mrs. The magic-number
						// error was correct and the whole profile died of it.
						//
						// The bytes are staged verbatim rather than replaced or dropped, so
						// what mihomo reads is what the user published and its own error
						// names a real cause. That is safe because ParseRuleProvider only
						// builds a FileVehicle (rules/provider/parse.go:50) and never reads
						// the file -- the read is Initial()'s, on the non-fatal path above.
						if err := stageRuntimeProviderFile(sourcePath, runtimePath); err != nil {
							return cleanupOnError(fmt.Errorf("hako: stage rule provider runtime: %w", err))
						}
						record.UnreadableWarn = prepareErr.Error()
						warnUnreadableRuleProvider(name, prepareErr)
					case len(stripped) > 0:
						if err := writeRuntimeProviderFile(runtimePath, prepared); err != nil {
							return cleanupOnError(fmt.Errorf("hako: stage rule provider runtime: %w", err))
						}
						record.MetadataNoops = encodeMetadataNoops(stripped)
						warnProviderMetadataNoops(name, stripped)
					default:
						if err := stageRuntimeProviderFile(sourcePath, runtimePath); err != nil {
							return cleanupOnError(fmt.Errorf("hako: stage rule provider runtime: %w", err))
						}
					}
				}
			} else {
				readStart := time.Now()
				payload, err := readBoundedRegularFile(sourcePath, int64(maximumProviderResourceBytes), "published provider")
				cost.readCount++
				cost.readNanos += time.Since(readStart).Nanoseconds()
				cost.readBytes += int64(len(payload))
				if err != nil {
					return cleanupOnError(fmt.Errorf("hako: stage proxy provider runtime: %w", err))
				}
				proxyStart := time.Now()
				prepared, stripped, err := sanitizeProxyProviderPayloadForIOS(format, payload, false)
				cost.proxyCount++
				cost.proxyNanos += time.Since(proxyStart).Nanoseconds()
				switch {
				case err != nil:
					if stageErr := stageRuntimeProviderFile(sourcePath, runtimePath); stageErr != nil {
						return cleanupOnError(fmt.Errorf("hako: stage proxy provider runtime: %w", stageErr))
					}
					record.UnreadableWarn = err.Error()
					warnUnreadableProxyProvider(name, err)
				case len(stripped) > 0:
					if err := writeRuntimeProviderFile(runtimePath, prepared); err != nil {
						return cleanupOnError(fmt.Errorf("hako: stage proxy provider runtime: %w", err))
					}
					record.EgressNoops = encodeEgressNoops(stripped)
					warnProviderEgressNoops(name, stripped)
				default:
					if err := stageRuntimeProviderFile(sourcePath, runtimePath); err != nil {
						return cleanupOnError(fmt.Errorf("hako: stage proxy provider runtime: %w", err))
					}
				}
			}
			cost.commitCount++
			cost.commitNanos += time.Since(commitStart).Nanoseconds()
			stagedInfo, err := os.Lstat(runtimePath)
			if err != nil {
				return cleanupOnError(fmt.Errorf("hako: stage %s provider runtime: %w", namespace.kind, err))
			}
			record.StagedSize = stagedInfo.Size()
			entryBehavior, _ := definition["behavior"].(string)
			entryFormat, _ := definition["format"].(string)
			if staged, readErr := os.ReadFile(runtimePath); readErr == nil {
				record.ContentSHA256 = stagedFileDigest(staged)
				if namespace.kind == "rule" {
					record.Count = stagedRuleSetCount(entryBehavior, entryFormat, staged)
				}
			}
			next.Entries[key] = record
			if namespace.kind == "rule" {
				logRuleProviderDisposition(name, record)
			}
			referenced[fileName] = struct{}{}
			runtime.entries[key] = providerRuntimeEntry{
				behavior: entryBehavior, format: entryFormat, sideUpdateSafe: sideUpdateSafe,
				compiled:    record.CompileVerdict == compileVerdictCompiled && record.Format != "mrs",
				runtimePath: runtimePath,
			}
			definition["path"] = runtimePath
		}
	}
	if runtime != nil {
		for _, record := range next.Entries {
			switch record.CompileVerdict {
			case compileVerdictCompiled:
				runtime.verdicts.compiled++
			case compileVerdictNotCompilable:
				runtime.verdicts.notCompilable++
			case compileVerdictKeptSource:
				runtime.verdicts.keptSource++
			}
		}
		startupStage(cost.line())
		saveStagedProviderManifest(parent, next)
		sweepStagedProviderRuntime(parent, stagedDirectory, referenced)
	}
	stripProviderSideUpdateMetadata(raw)
	return runtime, nil
}

func stripProviderSideUpdateMetadata(raw *config.RawConfig) {
	for _, definition := range raw.RuleProvider {
		delete(definition, providerSideUpdateSafeField)
	}
}

func providerRuntimeFileName(kind, name string) string {
	digest := sha256.Sum256([]byte(providerRuntimeKey(kind, name)))
	return hex.EncodeToString(digest[:]) + ".provider"
}

func providerRuntimeCompiledFileName(kind, name string) string {
	return providerRuntimeFileName(kind, name) + providerRuntimeCompiledSuffix
}

const providerRuntimeCompiledSuffix = ".mrs"

func pathInsideDirectory(path, directory string) bool {
	relative, err := filepath.Rel(directory, path)
	return err == nil && filepath.IsLocal(relative)
}

func providerSourceContained(sourcePath, home string) bool {
	if home == "" {
		return false
	}
	resolvedHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		resolvedHome = filepath.Clean(home)
	}
	resolved, err := filepath.EvalSymlinks(sourcePath)
	if err != nil {
		directory, file := filepath.Split(sourcePath)
		resolvedDirectory, dirErr := filepath.EvalSymlinks(filepath.Clean(directory))
		if dirErr != nil {
			return false
		}
		resolved = filepath.Join(resolvedDirectory, file)
	}
	return pathInsideDirectory(resolved, resolvedHome)
}

func stageRuntimeProviderFile(sourcePath, runtimePath string) error {
	before, err := os.Lstat(sourcePath)
	if err != nil {
		return fmt.Errorf("stat published provider: %w", err)
	}
	if !before.Mode().IsRegular() || before.Size() > int64(maximumProviderResourceBytes) {
		return fmt.Errorf("published provider is not a bounded regular file")
	}
	temporaryPath := runtimePath + ".staging"
	_ = os.Remove(temporaryPath)
	if err := os.Link(sourcePath, temporaryPath); err == nil {
		after, sourceErr := os.Lstat(sourcePath)
		shadow, shadowErr := os.Lstat(temporaryPath)
		if sourceErr == nil && shadowErr == nil && after.Mode().IsRegular() && shadow.Mode().IsRegular() &&
			os.SameFile(before, after) && os.SameFile(after, shadow) {
			if err := os.Rename(temporaryPath, runtimePath); err != nil {
				_ = os.Remove(temporaryPath)
				return err
			}
			return nil
		}
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("published provider changed while hard-linking")
	}

	if before.Size() == 0 {
		return writeRuntimeProviderFile(runtimePath, nil)
	}
	payload, err := readBoundedRegularFile(sourcePath, int64(maximumProviderResourceBytes), "published provider")
	if err != nil {
		return err
	}
	return writeRuntimeProviderFile(runtimePath, payload)
}

func writeRuntimeProviderFile(path string, payload []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".provider-update-")
	if err != nil {
		return err
	}
	temporaryPath := file.Name()
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(payload); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func ruleProviderSchemaError(behavior, format string) error {
	if _, err := P.ParseBehavior(behavior); err != nil {
		return fmt.Errorf("hako: provider behavior: %w", err)
	}
	if _, err := P.ParseRuleFormat(format); err != nil {
		return fmt.Errorf("hako: provider format: %w", err)
	}
	return nil
}

func prepareRuleProviderRuntimePayload(behavior, format string, payload []byte, policy appleRuntimePolicy) ([]byte, []providerMetadataNoop, error) {
	parsedBehavior, behaviorErr := P.ParseBehavior(behavior)
	if behaviorErr != nil {
		return nil, nil, fmt.Errorf("hako: provider behavior: %w", behaviorErr)
	}
	parsedFormat, formatErr := P.ParseRuleFormat(format)
	if formatErr != nil {
		return nil, nil, fmt.Errorf("hako: provider format: %w", formatErr)
	}
	if parsedBehavior == P.Classical && parsedFormat != P.MrsRule {
		return stageClassicalProviderPayloadForApple(payload, parsedFormat, policy.processMetadata())
	}
	if err := ValidateProviderForIOS("rule", behavior, format, payload); err != nil {
		return nil, nil, err
	}
	return payload, nil, nil
}

func logRuleProviderDisposition(name string, record stagedProviderRecord) {
	switch {
	case record.UnreadableWarn != "":
		log.Infoln("[Apple] rule provider %q: not readable by this core, loads no rules", name)
	case record.CompileVerdict == compileVerdictCompiled:
		log.Infoln("[Apple] rule provider %q: compiled to MRS", name)
	case record.CompileVerdict == compileVerdictKeptSource:
		log.Infoln("[Apple] rule provider %q: kept as source, every rule loads (%s)",
			name, record.CompileReason)
	default:
		log.Infoln("[Apple] rule provider %q: staged as source, not compiled on this profile", name)
	}
}

func logKeptSourceRuleProvider(name, reason string) {
	log.Infoln("[Apple] rule provider %q is kept as source and rides as text on this profile: %s", name, reason)
}

func warnUnreadableProxyProvider(name string, cause error) {
	log.Warnln("[Apple] proxy-provider %q cannot be read by this core and will load no proxies: %v; "+
		"the configuration still starts and every other provider is unaffected, "+
		"matching upstream warn-and-continue (hub/executor/executor.go:399). "+
		"Check the provider's url/path and that what it serves is a mihomo "+
		"`proxies:` document or a list of share links", name, cause)
}

func warnUnreadableRuleProvider(name string, cause error) {
	log.Warnln("[Apple] rule-provider %q cannot be read by this core and will load no rules: %v; "+
		"the configuration still starts and every other rule provider is unaffected, "+
		"matching upstream warn-and-continue (hub/executor/executor.go:333-337). "+
		"Check the provider's url/path and that its format matches the file it points at", name, cause)
}

func warnProviderMetadataNoops(name string, stripped []providerMetadataNoop) {
	for _, rule := range stripped {
		switch rule.reason {
		case providerNoopRuleUnsupported:
			log.Warnln("[Apple] rule-provider %q payload[%d] is not parseable or supported by this core and is skipped, matching upstream warn-and-continue; the remaining rules still load", name, rule.index)
		default:
			log.Warnln("[Apple] %s rule at rule-provider %q payload[%d] cannot execute in this Network Extension profile and is stripped from the private runtime copy (matches nothing, provider evaluation falls through)", rule.kind, name, rule.index)
		}
	}
}

func warnProviderEgressNoops(name string, stripped []providerEgressNoop) {
	for _, field := range stripped {
		log.Warnln("[Apple] proxy-provider %q payload[%d].%s has no Network Extension equivalent and is stripped from the private runtime copy; the provider still loads", name, field.index, field.field)
	}
}

func (runtime *providerRuntime) close() {
	if runtime == nil {
		return
	}
	runtime.directory = ""
	runtime.entries = nil
}

func (s *BoxService) sideUpdateProvider(kind, name string, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return fmt.Errorf("hako: provider runtime is unavailable")
	}
	if s.providerRuntime == nil {
		return sideUpdateRemoteProvider(kind, name, payload, currentRuntimePolicy(s.platform.UnderNetworkExtension()))
	}
	entry, exists := s.providerRuntime.entries[providerRuntimeKey(kind, name)]
	if !exists {
		return sideUpdateRemoteProvider(kind, name, payload, s.providerRuntime.policy)
	}
	if !entry.sideUpdateSafe {
		return fmt.Errorf("hako: provider affects Apple platform routes or lacks side-update metadata")
	}
	if entry.compiled {
		return fmt.Errorf("%sthis rule set runs compiled; the update applies at the next activation", SideUpdateDeferredPrefix)
	}
	runtimePayload := payload
	switch kind {
	case "rule":
		prepared, stripped, err := prepareRuleProviderRuntimePayload(entry.behavior, entry.format, payload, s.providerRuntime.policy)
		if err != nil {
			return err
		}
		runtimePayload = prepared
		warnProviderMetadataNoops(name, stripped)
	case "proxy":
		prepared, stripped, err := sanitizeProxyProviderPayloadForIOS(entry.format, payload, false)
		if err != nil {
			return err
		}
		runtimePayload = prepared
		warnProviderEgressNoops(name, stripped)
	default:
		return fmt.Errorf("hako: invalid provider kind")
	}
	rollbackPath := entry.runtimePath + ".rollback"
	_ = os.Remove(rollbackPath)
	if err := os.Link(entry.runtimePath, rollbackPath); err != nil {
		return fmt.Errorf("hako: preserve provider runtime rollback: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			_ = os.Remove(rollbackPath)
		}
	}()
	if err := writeRuntimeProviderFile(entry.runtimePath, runtimePayload); err != nil {
		_ = os.Remove(rollbackPath)
		return fmt.Errorf("hako: replace provider runtime: %w", err)
	}
	invalidateStagedProviderRecord(kind, name)

	var updateError error
	switch kind {
	case "proxy":
		provider, ok := tunnel.Providers()[name]
		if !ok || provider.VehicleType() != P.File {
			updateError = fmt.Errorf("hako: live proxy provider is unavailable")
		} else {
			updateError = provider.Update()
		}
	case "rule":
		provider, ok := tunnel.RuleProviders()[name]
		if !ok || provider.VehicleType() != P.File {
			updateError = fmt.Errorf("hako: live rule provider is unavailable")
		} else {
			updateError = provider.Update()
		}
	default:
		updateError = fmt.Errorf("hako: invalid provider kind")
	}
	if updateError == nil {
		committed = true
		return nil
	}
	if restoreError := os.Rename(rollbackPath, entry.runtimePath); restoreError != nil {
		return fmt.Errorf("hako: provider update failed and runtime rollback failed: %v", restoreError)
	}
	return fmt.Errorf("hako: provider update rejected: %w", updateError)
}

func stagedRuleSetCount(behavior, format string, staged []byte) int {
	if len(staged) == 0 {
		return 0
	}
	count, err := ProviderEntryCountForIOS("rule", behavior, format, staged)
	if err != nil || count < 0 {
		return 0
	}
	return count
}

type remoteSideUpdater interface {
	SideUpdate(payload []byte) error
}

func sideUpdateRemoteProvider(kind, name string, payload []byte, policy appleRuntimePolicy) error {
	var live P.Provider
	var prepared []byte
	switch kind {
	case "rule":
		provider, ok := tunnel.RuleProviders()[name]
		if !ok {
			return fmt.Errorf("hako: provider is not side-updateable")
		}
		formatted, ok := provider.(interface{ Format() P.RuleFormat })
		if !ok {
			return fmt.Errorf("hako: provider is not side-updateable")
		}
		next, stripped, err := prepareRuleProviderRuntimePayload(
			strings.ToLower(provider.Behavior().String()), ruleFormatSpelling(formatted.Format()), payload, policy)
		if err != nil {
			return err
		}
		warnProviderMetadataNoops(name, stripped)
		live, prepared = provider, next
	case "proxy":
		provider, ok := tunnel.Providers()[name]
		if !ok {
			return fmt.Errorf("hako: provider is not side-updateable")
		}
		next, stripped, err := sanitizeProxyProviderPayloadForIOS("", payload, false)
		if err != nil {
			return err
		}
		warnProviderEgressNoops(name, stripped)
		live, prepared = provider, next
	default:
		return fmt.Errorf("hako: invalid provider kind")
	}
	if live.VehicleType() != P.HTTP {
		return fmt.Errorf("hako: provider is not side-updateable")
	}
	updater, ok := live.(remoteSideUpdater)
	if !ok {
		return fmt.Errorf("hako: provider is not side-updateable")
	}
	if err := updater.SideUpdate(prepared); err != nil {
		return fmt.Errorf("hako: provider update rejected: %w", err)
	}
	return nil
}

func ruleFormatSpelling(format P.RuleFormat) string {
	switch format {
	case P.TextRule:
		return "text"
	case P.MrsRule:
		return "mrs"
	default:
		return "yaml"
	}
}
