package hako

import (
	"github.com/TokenPLS/Hako/dns"
)

func installLocalZoneResolver(enabled bool) {
	if !enabled || !mdnsSupported {
		dns.SetLocalZoneExchanger(nil)
		return
	}
	dns.SetLocalZoneExchanger(exchangeMulticastDNS)
}
