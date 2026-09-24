package hako

import (
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/TokenPLS/Hako/constant"
	"github.com/TokenPLS/Hako/constant/features"
)

const CommandSchemaVersion int32 = 1

const CommandSchemaMinVersion int32 = 1

func CheckCommandSchema(peerMin, peerCurrent int32) error {
	if peerMin <= 0 || peerCurrent < peerMin {
		return bridgeSafeError(errors.New("hako: invalid peer command schema range"))
	}
	if peerCurrent < CommandSchemaMinVersion || peerMin > CommandSchemaVersion {
		return bridgeSafeError(fmt.Errorf(
			"hako: incompatible command schema: local=%d...%d peer=%d...%d",
			CommandSchemaMinVersion, CommandSchemaVersion, peerMin, peerCurrent,
		))
	}
	return nil
}

func Version() string {
	return bridgeSafeString(constant.Version)
}

func GoVersion() string {
	return bridgeSafeString(runtime.Version() + ", " + runtime.GOOS + "/" + runtime.GOARCH)
}

func FreeMemory() {
	debug.FreeOSMemory()
}

func MemoryFootprint() int64 {
	return physFootprint()
}

func LowMemoryBuild() bool {
	return features.WithLowMemory
}

func TZProbe() string {
	now := hakoLocalTime(time.Now())
	return bridgeSafeString(fmt.Sprintf("loc=%s offset=%s now=%s",
		now.Location().String(),
		now.Format("-07:00"),
		now.Format("2006-01-02 15:04:05")))
}
