package hako

import (
	"strings"
	"testing"
)

func TestAllowLanIsNotHonouredUntilTheAppPermitsIt(t *testing.T) {
	const document = `
mixed-port: 7890
allow-lan: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	t.Cleanup(func() { SetAllowLanPermitted(false) })

	_, ours := parseBoth(t, document)
	if ours.General.AllowLan {
		t.Error("allow-lan was honoured without the app permitting it; a shipped user's " +
			"subscription would open a proxy on every network the device joins, with nobody " +
			"having pressed anything")
	}
	if ours.General.MixedPort != 7890 {
		t.Errorf("mixed-port = %d, want 7890 -- only the LAN exposure is gated, not the listener",
			ours.General.MixedPort)
	}
}

func TestAllowLanIsHonouredOnceTheAppPermitsIt(t *testing.T) {
	const document = `
mixed-port: 7890
allow-lan: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	SetAllowLanPermitted(true)
	t.Cleanup(func() { SetAllowLanPermitted(false) })

	mihomo, ours := parseBoth(t, document)
	if ours.General.AllowLan != mihomo.General.AllowLan {
		t.Errorf("allow-lan: mihomo %v, ours %v -- once permitted this is upstream's field again",
			mihomo.General.AllowLan, ours.General.AllowLan)
	}
}

func TestRevokingThePermissionTakesEffectOnTheNextParse(t *testing.T) {
	const document = `
mixed-port: 7890
allow-lan: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	SetAllowLanPermitted(true)
	t.Cleanup(func() { SetAllowLanPermitted(false) })
	if _, ours := parseBoth(t, document); !ours.General.AllowLan {
		t.Fatal("fixture is wrong: permitted parse did not honour allow-lan")
	}

	SetAllowLanPermitted(false)
	if _, ours := parseBoth(t, document); ours.General.AllowLan {
		t.Error("allow-lan survived the permission being revoked; a reload is the moment this " +
			"has to be re-read, not the next process launch")
	}
}

func TestGatingAllowLanIsReportedWithSomewhereToGo(t *testing.T) {
	const document = `
mixed-port: 7890
allow-lan: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	t.Cleanup(func() { SetAllowLanPermitted(false) })

	deviations, err := collectConfigDeviations(document, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	for _, deviation := range deviations {
		if deviation.Field != "allow-lan" {
			continue
		}
		if deviation.Alternative == "" {
			t.Error("the gate offers no alternative; a reader who wanted a LAN proxy is told no " +
				"and not told where yes lives")
		}
		if !strings.Contains(deviation.Source, "listener.go") {
			t.Errorf("source = %q, want the line that shows what allow-lan actually binds", deviation.Source)
		}
		SetAllowLanPermitted(true)
		after, _ := collectConfigDeviations(document, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
		for _, d := range after {
			if d.Field == "allow-lan" {
				t.Error("allow-lan is still reported as a deviation after the app permitted it")
			}
		}
		return
	}
	t.Error("allow-lan was gated and nothing was reported")
}

func TestPermissionAloneExposesNothingWithoutTheConfigurationAsking(t *testing.T) {
	const silentAboutLan = `
mixed-port: 7890
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	SetAllowLanPermitted(true)
	t.Cleanup(func() { SetAllowLanPermitted(false) })

	mihomo, ours := parseBoth(t, silentAboutLan)
	if ours.General.AllowLan {
		t.Error("the permission turned allow-lan on for a configuration that never asked for it; " +
			"the app-level switch is a ceiling, and a ceiling does not raise the floor")
	}
	if ours.General.AllowLan != mihomo.General.AllowLan {
		t.Errorf("allow-lan: mihomo %v, ours %v -- a configuration silent about allow-lan should "+
			"read the same on both", mihomo.General.AllowLan, ours.General.AllowLan)
	}
	if ours.General.MixedPort != 7890 {
		t.Errorf("mixed-port = %d, want 7890 -- the listener the user asked for still opens, on "+
			"127.0.0.1", ours.General.MixedPort)
	}
}
