package hako

import (
	"testing"

	"github.com/TokenPLS/Hako/component/geodata"
)

func resetGeodataFlagsForYardstick(t *testing.T) {
	t.Helper()
	geodata.SetCompiledGeoSiteOnly(false)
	geodata.SetCompiledGeoIPOnly(false)
	geodata.ClearGeoSiteCache()
	geodata.ClearGeoIPCache()
	resetGeoCountMemo()
}
