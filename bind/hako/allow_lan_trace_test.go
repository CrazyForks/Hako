package hako

import (
	"strings"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/log"
)

func TestEveryParseRecordsWhichWayTheGateWent(t *testing.T) {
	for _, permitted := range []bool{true, false} {
		SetAllowLanPermitted(permitted)
		t.Cleanup(func() { SetAllowLanPermitted(false) })

		subscription := log.Subscribe()
		done := make(chan string, 1)
		go func() {
			deadline := time.After(3 * time.Second)
			for {
				select {
				case event, open := <-subscription:
					if !open {
						done <- ""
						return
					}
					if strings.Contains(event.Payload, "allow-lan permitted") {
						done <- event.Payload
						return
					}
				case <-deadline:
					done <- ""
					return
				}
			}
		}()

		if _, err := parseConfigForIOS("proxies: []\nproxy-groups: []\nrules:\n  - MATCH,DIRECT\n", true); err != nil {
			log.UnSubscribe(subscription)
			t.Fatalf("parse: %v", err)
		}
		line := <-done
		log.UnSubscribe(subscription)

		if line == "" {
			t.Errorf("permitted=%v: no line records which way the gate went. A configuration "+
				"with no listeners leaves no address to read back, so this is the only record "+
				"that the dangerous state was or was not armed", permitted)
			continue
		}
		want := "permitted=false"
		if permitted {
			want = "permitted=true"
		}
		if !strings.Contains(line, want) {
			t.Errorf("permitted=%v: line says %q, want it to contain %q", permitted, line, want)
		}
	}
}
