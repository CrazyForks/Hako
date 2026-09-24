package hako

import (
	"github.com/TokenPLS/Hako/listener/inner"
	"testing"
)

func TestIndependentInternalInboundsAfterCoreShutdown(t *testing.T) {
	old := inner.GetTunnel()
	inner.CloseTCPConnections()
	defer inner.New(old)
	t.Run("Reality", TestControlledRealityInterop)
	t.Run("Hysteria2Realm", TestControlledHysteria2RealmInterop)
}
