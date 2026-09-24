package dns

import (
	"github.com/TokenPLS/Hako/adapter/inbound"
	"testing"
)

func TestHakoProductionListenConfigOffersCompanions(t *testing.T) {
	var lc interface{} = inbound.NewListenConfig()
	if _, ok := lc.(loopbackPacketCompanions); !ok {
		t.Fatalf("%T does not offer loopback companions", lc)
	}
}
