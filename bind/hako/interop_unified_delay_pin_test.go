package hako

import (
	"testing"

	"github.com/TokenPLS/Hako/adapter"
)

func pinUnifiedDelayOff(t *testing.T) {
	t.Helper()
	prior := adapter.UnifiedDelay.Swap(false)
	t.Cleanup(func() { adapter.UnifiedDelay.Store(prior) })
}
