package hako

import (
	"time"

	"github.com/dlclark/regexp2"
)

const maximumRegularExpressionMatchDurationForIOS = 100 * time.Millisecond

func init() {
	regexp2.DefaultMatchTimeout = maximumRegularExpressionMatchDurationForIOS
}
