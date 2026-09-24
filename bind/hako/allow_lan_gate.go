package hako

import "sync/atomic"

var allowLanPermitted atomic.Bool

func SetAllowLanPermitted(permitted bool) {
	allowLanPermitted.Store(permitted)
}

func AllowLanPermitted() bool {
	return allowLanPermitted.Load()
}
