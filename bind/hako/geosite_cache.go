package hako

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/TokenPLS/Hako/component/geodata"
	"github.com/TokenPLS/Hako/component/geodata/compiled"
	C "github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/log"
	"gopkg.in/yaml.v3"
)

func GeoSiteCategoriesIn(content string) []string {
	lowered := strings.ToLower(content)

	isCategoryByte := func(b byte) bool {
		switch {
		case b >= 'a' && b <= 'z', b >= '0' && b <= '9':
			return true
		case b == '-', b == '_', b == '.', b == '@', b == '!':
			return true
		}
		return false
	}
	atBoundary := func(index int) bool {
		return index == 0 || !isCategoryByte(lowered[index-1])
	}

	seen := make(map[string]struct{})
	var found []string
	collect := func(name string) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			return
		}
		for i := 0; i < len(name); i++ {
			if !isCategoryByte(name[i]) {
				return
			}
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		found = append(found, name)
	}

	endsSegment := func(b byte) bool {
		switch b {
		case '\n', '\r', '"', '\'', ':', ']', '#', '(', ')':
			return true
		}
		return false
	}
	isSpace := func(b byte) bool { return b == ' ' || b == '\t' }
	const word = "geosite"
	for offset := 0; ; {
		index := strings.Index(lowered[offset:], word)
		if index < 0 {
			break
		}
		index += offset
		offset = index + len(word)
		if !atBoundary(index) {
			continue
		}
		next := offset
		for next < len(lowered) && isSpace(lowered[next]) {
			next++
		}
		var start int
		var wantEveryPiece bool
		switch {
		case next < len(lowered) && lowered[next] == ',':
			start, wantEveryPiece = next+1, false
		case next == offset && next < len(lowered) && lowered[next] == ':':
			start, wantEveryPiece = next+1, true
		default:
			continue
		}
		end := start
		for end < len(lowered) && !endsSegment(lowered[end]) {
			end++
		}
		if end < len(lowered) && lowered[end] == ':' && strings.HasPrefix(lowered[end+1:], "//") {
			offset = end
			continue
		}
		pieces := strings.Split(lowered[start:end], ",")
		if !wantEveryPiece && len(pieces) > 1 {
			pieces = pieces[:1]
		}
		for _, piece := range pieces {
			collect(piece)
		}
		offset = end
	}
	collectFallbackFilterGeoSite(content, collect)
	return found
}

func collectFallbackFilterGeoSite(content string, collect func(string)) {
	var document struct {
		DNS struct {
			FallbackFilter struct {
				GeoSite []string `yaml:"geosite"`
			} `yaml:"fallback-filter"`
		} `yaml:"dns"`
	}
	if yaml.Unmarshal([]byte(content), &document) != nil {
		return
	}
	for _, category := range document.DNS.FallbackFilter.GeoSite {
		collect(category)
	}
}

func PrepareGeoSiteCache(content string) (string, error) {
	categories := GeoSiteCategoriesIn(content)
	if len(categories) == 0 {
		return "geosite: no categories named", nil
	}
	previous := geodata.CompiledGeoSiteOnly()
	geodata.SetCompiledGeoSiteOnly(false)
	defer geodata.SetCompiledGeoSiteOnly(previous)

	sourceModified := time.Time{}
	if info, err := os.Stat(C.Path.GeoSite()); err == nil {
		sourceModified = info.ModTime()
	}

	prepared, reused := 0, 0
	var failures []string
	for _, category := range categories {
		if path, err := compiled.Path(geodata.CompiledGeoSiteDir(), category); err == nil {
			if info, err := os.Stat(path); err == nil && info.ModTime().After(sourceModified) {
				if count, err := compiled.EntryCount(
					geodata.CompiledGeoSiteDir(), category,
				); err == nil && count > 0 {
					reused++
					continue
				}
			}
		}
		if err := geodata.CompileGeoSite(category); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %s", category, err))
			continue
		}
		prepared++
	}
	summary := fmt.Sprintf("geosite: %d compiled, %d current, %d failed of %d named, dir=%s",
		prepared, reused, len(categories)-prepared-reused, len(categories),
		geodata.CompiledGeoSiteDir())
	if len(failures) > 0 {
		summary += " | " + strings.Join(failures, "; ")
		log.Warnln("[Apple] geosite: %d of %d named categories will match nothing (compile failed): %s",
			len(failures), len(categories), strings.Join(failures, "; "))
	}
	log.Infoln("[Apple] %s", summary)
	geodata.ClearGeoSiteCache()
	return bridgeSafeString(summary), nil
}

func GeoSiteCategoryLines(content string) string {
	return bridgeSafeString(strings.Join(GeoSiteCategoriesIn(content), "\n"))
}
