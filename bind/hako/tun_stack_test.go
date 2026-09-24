package hako

import (
	"testing"

	C "github.com/TokenPLS/Hako/constant"
)

func TestSilentConfigurationStillGetsGvisor(t *testing.T) {
	const document = `
tun:
  enable: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, document)
	if mihomo.General.Tun.Stack != C.TunGvisor {
		t.Fatalf("fixture is wrong, not the code: upstream parsed a silent tun.stack as %v, so "+
			"gVisor is not the zero value and removing the override WOULD change the default",
			mihomo.General.Tun.Stack)
	}

	finalizeConfigForIOS(ours, true)

	if ours.General.Tun.Stack != C.TunGvisor {
		t.Errorf("a configuration that never mentioned tun.stack got %v; the default has to stay "+
			"exactly where the device A/B left it", ours.General.Tun.Stack)
	}
}

func TestAnExplicitStackIsHonoured(t *testing.T) {
	for name, stack := range map[string]C.TUNStack{
		"system": C.TunSystem,
		"mixed":  C.TunMixed,
		"gvisor": C.TunGvisor,
	} {
		t.Run(name, func(t *testing.T) {
			document := `
tun:
  enable: true
  stack: ` + name + `
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
			mihomo, ours := parseBoth(t, document)
			if mihomo.General.Tun.Stack != stack {
				t.Fatalf("fixture is wrong: upstream parsed %q as %v", name, mihomo.General.Tun.Stack)
			}

			finalizeConfigForIOS(ours, true)

			if ours.General.Tun.Stack != mihomo.General.Tun.Stack {
				t.Errorf("tun.stack: mihomo %v, ours %v -- the capability was measured under this "+
					"extension's own entitlements and nothing in it is denied, so there is no "+
					"platform fact left to override the user with",
					mihomo.General.Tun.Stack, ours.General.Tun.Stack)
			}
		})
	}
}

func TestTunStackNoLongerAppearsInTheDeviationReport(t *testing.T) {
	const document = `
tun:
  enable: true
  stack: system
  mtu: 1400
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	deviations, err := collectConfigDeviations(document, currentRuntimePolicy(true))
	if err != nil {
		t.Fatalf("collect deviations: %v", err)
	}
	for _, deviation := range deviations {
		if deviation.Field == "tun.stack" {
			t.Errorf("tun.stack is still reported as %q -- it is honoured now, so the entry is a "+
				"false statement rendered verbatim to a user", deviation.Effective)
		}
	}

	sawTunMTU := false
	for _, deviation := range deviations {
		if deviation.Field == "tun.mtu" {
			sawTunMTU = true
		}
	}
	if !sawTunMTU {
		t.Fatal("the deviation walk reported nothing for tun.mtu either, so this test proved " +
			"nothing about tun.stack -- it measured an empty list")
	}
}
