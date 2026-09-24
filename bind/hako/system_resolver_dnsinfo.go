package hako

import "github.com/TokenPLS/Hako/common/atomic"

var unscopedResolversArePhysical = atomic.NewBool(true)

func setUnscopedResolversArePhysical(value bool) {
	unscopedResolversArePhysical.Store(value)
}
