package hako

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/component/dialer"
	"github.com/TokenPLS/Hako/component/pause"
	"github.com/TokenPLS/Hako/dns"
	D "github.com/miekg/dns"
)

type witnessHarness struct {
	*bearerWitness
	clock     time.Time
	verdicts  chan string
	mu        sync.Mutex
	bound     []string
	unbound   []string
	asked     []string
	boundErr  error
	unbErr    error
	askErr    error
	resolvers []string
	closedAt  []time.Time
	scheduled []scheduledCall
	marked    bool
	silences  int
	resets    int
	checks    int
	actions   []string
}

type scheduledCall struct {
	after time.Duration
	run   func()
}

func newWitnessHarness(t *testing.T) *witnessHarness {
	t.Helper()
	h := &witnessHarness{clock: time.Unix(1_800_000_000, 0), verdicts: make(chan string, 8), resolvers: []string{"198.51.100.53:53"}}
	h.bearerWitness = &bearerWitness{
		now: func() time.Time { return h.clock },
		dialBound: func(_ context.Context, address string) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.bound = append(h.bound, address)
			return h.boundErr
		},
		dialUnbound: func(_ context.Context, address string) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.unbound = append(h.unbound, address)
			return h.unbErr
		},
		askResolver: func(_ context.Context, endpoint string) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.asked = append(h.asked, endpoint)
			return h.askErr
		},
		pathResolvers: func(int32) []string {
			h.mu.Lock()
			defer h.mu.Unlock()
			return h.resolvers
		},
		closeFlowsBefore: func(at time.Time) int {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.closedAt = append(h.closedAt, at)
			return 3
		},
		schedule: func(after time.Duration, run func()) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.scheduled = append(h.scheduled, scheduledCall{after, run})
		},
		report: func(verdict string) {
			if strings.Contains(verdict, "recovery attempt") || strings.Contains(verdict, "bound to the dead interface are closed") {
				h.mu.Lock()
				h.actions = append(h.actions, verdict)
				h.mu.Unlock()
				return
			}
			h.verdicts <- verdict
		},
		setSilent: func(silent bool) {
			h.mu.Lock()
			defer h.mu.Unlock()
			if silent && !h.marked {
				h.silences++
			}
			h.marked = silent
		},
		resetNetwork: func() {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.resets++
		},
		checkEveryProvider: func() {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.checks++
		},
	}
	previous := publishedInterfaceIndex.Load()
	publishedInterfaceIndex.Store(9)
	t.Cleanup(func() { publishedInterfaceIndex.Store(previous) })
	return h
}

func (h *witnessHarness) verdict(t *testing.T) string {
	t.Helper()
	select {
	case v := <-h.verdicts:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("the witness never spoke")
		return ""
	}
}

func (h *witnessHarness) silent(t *testing.T) {
	t.Helper()
	select {
	case v := <-h.verdicts:
		t.Fatalf("the witness spoke when it should not have: %s", v)
	case <-time.After(100 * time.Millisecond):
	}
}

func (h *witnessHarness) timeout(kind, address string, err error) {
	h.observe(kind, "tcp", address, dialer.PhysicalDialStarted, nil)
	h.observe(kind, "tcp", address, dialer.PhysicalDialFailed, err)
}

func (h *witnessHarness) question(endpoint string, err error) {
	h.observe(dialer.DialKindResolver, "udp", endpoint, dialer.PhysicalDialStarted, nil)
	if err == nil {
		h.observe(dialer.DialKindResolver, "udp", endpoint, dialer.PhysicalDialSucceeded, nil)
		return
	}
	h.observe(dialer.DialKindResolver, "udp", endpoint, dialer.PhysicalDialFailed, err)
}

func (h *witnessHarness) connected(kind, address string) {
	h.observe(kind, "tcp", address, dialer.PhysicalDialStarted, nil)
	h.observe(kind, "tcp", address, dialer.PhysicalDialSucceeded, nil)
}

func mustContain(t *testing.T, verdict string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(verdict, want) {
			t.Fatalf("verdict must say %q, got: %s", want, verdict)
		}
	}
}

var errIOTimeout = &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}

const relay = "203.0.113.9:8102"

func TestFiveProxyServerTimeoutsRunTheWitnessAndTheLineNamesEveryAnswer(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr = errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, context.DeadlineExceeded)
	}
	verdict := h.verdict(t)
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.bound) != 1 || len(h.unbound) != 1 || h.bound[0] != relay || h.unbound[0] != relay {
		t.Fatalf("the witness dials the last address that timed out, once each way; bound=%v unbound=%v", h.bound, h.unbound)
	}
	if len(h.asked) != 1 || h.asked[0] != "198.51.100.53:53" {
		t.Fatalf("the witness asks the path's own resolver, got %v", h.asked)
	}
	mustContain(t, verdict, "5 dials in a row timed out", "the last to a proxy server at "+relay, "interface index 9",
		"bound: dial tcp", "unbound: connected", "the binding is what is dead")
}

func TestOnlySilenceCountsAndAnyConnectEndsTheRun(t *testing.T) {
	h := newWitnessHarness(t)
	for i := 0; i < bearerWitnessAfter-1; i++ {
		h.timeout(dialer.DialKindDirect, "203.0.113.9:443", errIOTimeout)
	}
	h.timeout(dialer.DialKindDirect, "203.0.113.9:443", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)})
	h.timeout(dialer.DialKindDirect, "203.0.113.9:443", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)})
	h.observe(dialer.DialKindDirect, "udp", "203.0.113.9:443", dialer.PhysicalDialStarted, nil)
	h.observe(dialer.DialKindDirect, "udp", "203.0.113.9:443", dialer.PhysicalDialFailed, errIOTimeout)
	h.timeout("", "127.0.0.1:7874", errIOTimeout)
	h.silent(t)

	h.connected(dialer.DialKindProxy, relay)
	h.timeout(dialer.DialKindDirect, "203.0.113.9:443", errIOTimeout)
	h.silent(t)
	if h.timeouts != 1 {
		t.Fatalf("a connect must reset the run, timeouts=%d", h.timeouts)
	}
}

func TestTheWitnessSpeaksOnceAMinute(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr, h.unbErr, h.askErr = errIOTimeout, errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	h.verdict(t)
	for i := 0; i < 3*bearerWitnessAfter; i++ {
		h.clock = h.clock.Add(time.Second)
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	h.silent(t)
	h.clock = h.clock.Add(bearerWitnessInterval)
	h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	h.verdict(t)
}

func TestTheWitnessWaitsForAPublishedPath(t *testing.T) {
	h := newWitnessHarness(t)
	publishedInterfaceIndex.Store(0)
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	h.silent(t)
	publishedInterfaceIndex.Store(9)
	h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	h.verdict(t)
}

func TestIsDialTimeoutRecognisesEveryFormOfSilence(t *testing.T) {
	for _, err := range []error{
		context.DeadlineExceeded,
		os.ErrDeadlineExceeded,
		errIOTimeout,
		errors.Join(errors.New("connect failed"), errIOTimeout),
	} {
		if !isDialTimeout(err) {
			t.Fatalf("%v is silence", err)
		}
	}
	for _, err := range []error{
		nil,
		errors.New("dns resolve failed"),
		&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)},
	} {
		if isDialTimeout(err) {
			t.Fatalf("%v is an answer, not silence", err)
		}
	}
}

func TestDialHealthCarriesTheWitnessOnceItHasSpoken(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr, h.unbErr = errIOTimeout, errIOTimeout
	previous := witness
	witness = h.bearerWitness
	t.Cleanup(func() { witness = previous })

	if strings.Contains(DialHealthJSON(), "bearerWitness") {
		t.Fatal("the witness must be absent from the health document until it has spoken")
	}
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	h.verdict(t)
	health := DialHealthJSON()
	for _, want := range []string{`"bearerWitness"`, `"kind":"destination"`, `"address":"` + relay + `"`, `"dialKind":"proxy"`, `"resolver":"198.51.100.53:53"`, `"bindingSuspended":false`} {
		if !strings.Contains(health, want) {
			t.Fatalf("health must carry %s, got %s", want, health)
		}
	}
}

func TestTheBindingIsSuspendedOnlyWhenTheWitnessFindsItDead(t *testing.T) {
	cases := []struct {
		name          string
		boundErr      error
		unbErr        error
		wantSuspended bool
		wantKind      string
	}{
		{"unbound connects, bound does not", errIOTimeout, nil, true, "binding"},
		{"both connect", nil, nil, false, "carries"},
		{"neither connects, the resolver answers", errIOTimeout, errIOTimeout, false, "destination"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearBindingSuspension()
			t.Cleanup(clearBindingSuspension)
			h := newWitnessHarness(t)
			h.boundErr, h.unbErr = tc.boundErr, tc.unbErr
			for i := 0; i < bearerWitnessAfter; i++ {
				h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
			}
			h.verdict(t)
			if got := bindingSuspended(9); got != tc.wantSuspended {
				t.Fatalf("binding suspended=%v, want %v", got, tc.wantSuspended)
			}
			if h.lastKind != tc.wantKind {
				t.Fatalf("verdict kind %q, want %q", h.lastKind, tc.wantKind)
			}
		})
	}
}

func TestAnAnsweringResolverMakesItTheDestinationsSilence(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr, h.unbErr = errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	verdict := h.verdict(t)
	mustContain(t, verdict, "the network delivers", "198.51.100.53:53 answered", "the proxy server at "+relay+" is unreachable, not the link")
	if len(h.closedAt) != 0 {
		t.Fatalf("a destination's silence closes nothing, got %v", h.closedAt)
	}
}

func TestNothingAnsweringIsTheNetworksSilence(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr, h.unbErr, h.askErr = errIOTimeout, errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindDirect, "203.0.113.9:443", errIOTimeout)
	}
	verdict := h.verdict(t)
	mustContain(t, verdict, "the last to 203.0.113.9:443", "198.51.100.53:53 is silent too", "the network itself is not delivering")
	if h.lastKind != "network" {
		t.Fatalf("verdict kind %q, want network", h.lastKind)
	}
}

func TestAPathWithNoResolverIsSaidOutLoud(t *testing.T) {
	h := newWitnessHarness(t)
	h.resolvers = nil
	h.boundErr, h.unbErr = errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	verdict := h.verdict(t)
	mustContain(t, verdict, "this path lists no resolver to ask", "cannot tell the network's silence from the destination's")
	if len(h.asked) != 0 {
		t.Fatalf("nothing to ask, got %v", h.asked)
	}
	if h.lastKind != witnessUnknown || h.marked || !h.outageSince.IsZero() || len(h.actions) != 0 {
		t.Fatalf("kind=%q marked=%v outage=%v actions=%v, want an unknown verdict that moves nothing", h.lastKind, h.marked, h.outageSince, h.actions)
	}
}

func TestTheFirstConnectAfterTheNetworksSilenceClosesTheFlowsThatWereFrozen(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr, h.unbErr, h.askErr = errIOTimeout, errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	h.verdict(t)
	verdictAt := h.clock
	h.clock = h.clock.Add(90 * time.Second)
	h.connected(dialer.DialKindProxy, relay)
	recovery := h.verdict(t)
	mustContain(t, recovery, "the network delivers again", "1m30s", "3 connections opened before")
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.closedAt) != 2 || !h.closedAt[0].Equal(verdictAt) || !h.closedAt[1].Equal(verdictAt) {
		t.Fatalf("the flows closed are those opened before the verdict at %v, got %v", verdictAt, h.closedAt)
	}
	h.mu.Unlock()
	h.connected(dialer.DialKindProxy, relay)
	h.silent(t)
	h.mu.Lock()
	if len(h.closedAt) != 2 {
		t.Fatalf("recovery runs once per outage, got %v", h.closedAt)
	}
}

func TestAPathUpdateEndsTheBindingSuspension(t *testing.T) {
	clearBindingSuspension()
	t.Cleanup(clearBindingSuspension)
	suspendBinding(9)
	if !bindingSuspended(9) {
		t.Fatal("suspended")
	}
	clearBindingSuspension()
	if bindingSuspended(9) {
		t.Fatal("a path update must end the suspension")
	}
}

func TestFiveStalledDialsTriggerTheWitnessBeforeAnyTimesOut(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr, h.unbErr = errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessPending-1; i++ {
		h.observe(dialer.DialKindProxy, "tcp", relay, dialer.PhysicalDialStarted, nil)
	}
	h.clock = h.clock.Add(bearerWitnessStall)
	h.observe(dialer.DialKindProxy, "tcp", relay, dialer.PhysicalDialStarted, nil)
	verdict := h.verdict(t)
	mustContain(t, verdict, "5 dials waiting unanswered")
}

func TestARecentConnectKeepsTheWitnessQuiet(t *testing.T) {
	h := newWitnessHarness(t)
	for i := 0; i < bearerWitnessPending; i++ {
		h.observe(dialer.DialKindProxy, "tcp", relay, dialer.PhysicalDialStarted, nil)
	}
	h.clock = h.clock.Add(bearerWitnessStall - 500*time.Millisecond)
	h.connected(dialer.DialKindDirect, "203.0.113.9:443")
	h.clock = h.clock.Add(500 * time.Millisecond)
	h.observe(dialer.DialKindProxy, "tcp", relay, dialer.PhysicalDialStarted, nil)
	h.silent(t)
}

func TestResolverEndpointsTakeEveryShapeThePlatformLists(t *testing.T) {
	for line, want := range map[string]string{
		"10.0.0.1":        "10.0.0.1:53",
		"10.0.0.1:5353":   "10.0.0.1:5353",
		"[fe80::1]:53":    "[fe80::1]:53",
		"2001:db8::1":     "[2001:db8::1]:53",
		"fe80::1%pdp_ip0": "[fe80::1%pdp_ip0]:53",
		"not an address":  "",
	} {
		if got := resolverEndpoint(line); got != want {
			t.Fatalf("%q -> %q, want %q", line, got, want)
		}
	}
}

func TestFiveSocketsStartingAtOnceRunTheWitnessWhenTheStallWindowClosesWithNoOtherEvent(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr, h.unbErr = errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessPending; i++ {
		h.observe(dialer.DialKindProxy, "tcp", relay, dialer.PhysicalDialStarted, nil)
	}
	h.mu.Lock()
	if len(h.scheduled) != 1 || h.scheduled[0].after != bearerWitnessStall {
		h.mu.Unlock()
		t.Fatalf("the fifth socket in flight arms one timer for the stall window, got %d", len(h.scheduled))
	}
	fire := h.scheduled[0].run
	h.mu.Unlock()
	h.silent(t)
	h.clock = h.clock.Add(bearerWitnessStall)
	fire()
	mustContain(t, h.verdict(t), "5 dials waiting unanswered")
}

func TestTheStallTimerFindsNothingWhenASocketConnectedMeanwhile(t *testing.T) {
	h := newWitnessHarness(t)
	for i := 0; i < bearerWitnessPending; i++ {
		h.observe(dialer.DialKindProxy, "tcp", relay, dialer.PhysicalDialStarted, nil)
	}
	h.clock = h.clock.Add(time.Second)
	h.connected(dialer.DialKindDirect, "203.0.113.9:443")
	h.clock = h.clock.Add(time.Second)
	h.mu.Lock()
	fire := h.scheduled[0].run
	h.mu.Unlock()
	fire()
	h.silent(t)
}

func TestTheWitnessOwnDialsAreNotCounted(t *testing.T) {
	h := newWitnessHarness(t)
	for i := 0; i < bearerWitnessAfter+2; i++ {
		h.timeout(witnessDialKind, relay, errIOTimeout)
	}
	h.silent(t)
	if h.timeouts != 0 {
		t.Fatalf("the witness's own dials must not count, timeouts=%d", h.timeouts)
	}
}

func TestTheSystemStacksConnectTurnsTheNetworksSilenceIntoTheProcesss(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr, h.unbErr, h.askErr = errIOTimeout, errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	h.verdict(t)
	h.observe(dialer.DialKindDirect, "tcp", "198.51.100.7:443", dialer.PhysicalDialStarted, nil)
	health, _ := h.health()
	if health["address"] != relay {
		t.Fatalf("DialHealthJSON must hand the platform the verdict's address, got %v", health["address"])
	}
	h.systemStackReported(relay, h.lastAt.Unix(), true, 83, "")
	line := h.verdict(t)
	mustContain(t, line, "[Apple] bearer witness: the system's own stack connected to 203.0.113.9:8102 in 83ms",
		"this process's sockets could not", "the silence is this process's, not the bearer's")
	if h.lastKind != witnessProcess {
		t.Fatalf("kind %q, want process", h.lastKind)
	}
	health, _ = h.health()
	if health["systemStack"] != "connected in 83ms" || health["kind"] != witnessProcess {
		t.Fatalf("health %v", health)
	}
}

func TestTheSystemStacksSilenceConfirmsTheNetworks(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr, h.unbErr, h.askErr = errIOTimeout, errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	h.verdict(t)
	h.systemStackReported(relay, h.lastAt.Unix(), false, 2000, "i/o timeout")
	line := h.verdict(t)
	mustContain(t, line, "the system's own stack could not connect to 203.0.113.9:8102 either: i/o timeout in 2s",
		"the bearer is silent for every stack on this device")
	if h.lastKind != witnessNetwork {
		t.Fatalf("kind %q, want network", h.lastKind)
	}
	health, _ := h.health()
	if health["systemStack"] != "i/o timeout in 2s" {
		t.Fatalf("health %v", health)
	}
}

func TestASystemStackReportForAnotherAddressChangesNothing(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr, h.unbErr, h.askErr = errIOTimeout, errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	h.verdict(t)
	h.systemStackReported("198.51.100.7:443", h.lastAt.Unix(), true, 40, "")
	line := h.verdict(t)
	mustContain(t, line, "the system's own stack connected to 198.51.100.7:443 in 40ms", "not for the verdict in force (203.0.113.9:8102 at")
	if h.lastKind != witnessNetwork {
		t.Fatalf("kind %q, want network unchanged", h.lastKind)
	}
	if _, has := func() (any, bool) { health, _ := h.health(); v, ok := health["systemStack"]; return v, ok }(); has {
		t.Fatal("a mismatched report must not be recorded as the verdict's system-stack answer")
	}
}

func TestUnansweredResolverQuestionsRunTheWitness(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr, h.unbErr, h.askErr = errIOTimeout, errIOTimeout, errIOTimeout
	h.connected(dialer.DialKindProxy, relay)
	for i := 0; i < bearerWitnessAfter; i++ {
		h.question("198.51.100.53:53", errIOTimeout)
	}
	verdict := h.verdict(t)
	mustContain(t, verdict, "5 dials in a row timed out, the last a question to the resolver at 198.51.100.53:53",
		"the network itself is not delivering")
	if len(h.bound) != 1 || h.bound[0] != relay {
		t.Fatalf("bound dials %v, want the last TCP address %s", h.bound, relay)
	}
}

func TestAResolverThatAnswersEndsTheNetworksSilence(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr, h.unbErr, h.askErr = errIOTimeout, errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	h.verdict(t)
	h.clock = h.clock.Add(40 * time.Second)
	h.question("198.51.100.53:53", nil)
	line := h.verdict(t)
	mustContain(t, line, "the network delivers again, 40s after it was found silent", "3 connections opened before that verdict are closed")
}

func TestAResolverAloneIsWhatTheWitnessDials(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr, h.unbErr, h.askErr = errIOTimeout, errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.question("198.51.100.53:53", errIOTimeout)
	}
	verdict := h.verdict(t)
	mustContain(t, verdict, "the last a question to the resolver at 198.51.100.53:53")
	if len(h.bound) != 1 || h.bound[0] != "198.51.100.53:53" {
		t.Fatalf("bound dials %v, want the resolver", h.bound)
	}
}

func TestTheNetworksSilenceMarksTheBearerSilentUntilItDeliversAgain(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr, h.unbErr, h.askErr = errIOTimeout, errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	h.verdict(t)
	if !h.marked || h.silences != 1 {
		t.Fatalf("silent=%v silences=%d after the network verdict, want marked once", h.marked, h.silences)
	}
	h.connected(dialer.DialKindProxy, relay)
	h.verdict(t)
	if h.marked {
		t.Fatal("the first connect after the outage must clear the mark")
	}
}

func TestADestinationsSilenceMarksNothing(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr, h.unbErr = errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	h.verdict(t)
	if h.marked || h.silences != 0 {
		t.Fatalf("silent=%v silences=%d under a destination verdict, want none", h.marked, h.silences)
	}
}

func TestTheWitnessLooksAgainInsideItsOwnSilenceAndFindsTheNetworkBack(t *testing.T) {
	h := newWitnessHarness(t)
	pause.SetBearerSilent(false)
	h.setSilent = func(silent bool) {
		pause.SetBearerSilent(silent)
		h.mu.Lock()
		h.marked = silent
		h.mu.Unlock()
	}
	t.Cleanup(func() { pause.SetBearerSilent(false) })
	h.boundErr, h.unbErr, h.askErr = errIOTimeout, errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	h.verdict(t)
	if !pause.IsBearerSilent() || pause.IsNetworkPaused() {
		t.Fatalf("bearerSilent=%v networkPaused=%v, want the witness's own bit only", pause.IsBearerSilent(), pause.IsNetworkPaused())
	}
	h.clock = h.clock.Add(bearerWitnessInterval)
	h.mu.Lock()
	h.boundErr = nil
	h.mu.Unlock()
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	verdict := h.verdict(t)
	mustContain(t, verdict, "the bound path carries")
	if pause.IsBearerSilent() || !h.outageSince.IsZero() {
		t.Fatal("a carrying verdict must end the outage and the mark")
	}
}

func TestAnyOtherVerdictEndsTheMarkAndALaterOutageMarksAgain(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr, h.unbErr, h.askErr = errIOTimeout, errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	h.verdict(t)
	h.clock = h.clock.Add(bearerWitnessInterval)
	h.mu.Lock()
	h.askErr = nil
	h.mu.Unlock()
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	mustContain(t, h.verdict(t), "is unreachable, not the link")
	mustContain(t, h.verdict(t), "the network delivers again")
	if h.marked {
		t.Fatal("a destination verdict ends the network's silence")
	}
	h.clock = h.clock.Add(bearerWitnessInterval)
	h.mu.Lock()
	h.askErr = errIOTimeout
	h.mu.Unlock()
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	h.verdict(t)
	if !h.marked || h.silences != 2 {
		t.Fatalf("silent=%v silences=%d, want the second outage marked", h.marked, h.silences)
	}
}

func TestTheWitnessNeverTouchesTheMonitorsPause(t *testing.T) {
	pause.NetworkPause()
	t.Cleanup(pause.NetworkWake)
	w := newBearerWitness()
	w.mu.Lock()
	w.setOutageLocked(time.Unix(1_800_000_000, 0))
	w.setOutageLocked(time.Time{})
	w.mu.Unlock()
	w.reset()
	if !pause.IsNetworkPaused() {
		t.Fatal("the monitor's no-path pause was lifted by the witness")
	}
	pause.SetBearerSilent(false)
}

func TestTheEndOfASessionResetsTheWitnessAndLiftsItsPause(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr, h.unbErr, h.askErr = errIOTimeout, errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	h.verdict(t)
	h.waitActions(t, 1)
	h.mu.Lock()
	closedBefore := len(h.closedAt)
	h.mu.Unlock()
	h.reset()
	if _, spoke := h.health(); spoke {
		t.Fatal("a reset witness has not spoken")
	}
	if h.marked {
		t.Fatal("a reset must clear the bearer-silent mark")
	}
	h.connected(dialer.DialKindProxy, relay)
	h.silent(t)
	if len(h.closedAt) != closedBefore {
		t.Fatalf("no outage to recover from after a reset, yet flows were closed at %v", h.closedAt[closedBefore:])
	}
}

func TestAnExperimentLandingAfterTheResetIsDropped(t *testing.T) {
	h := newWitnessHarness(t)
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	h.dialBound = func(context.Context, string) error {
		started <- struct{}{}
		<-release
		return errIOTimeout
	}
	h.unbErr, h.askErr = errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	<-started
	h.reset()
	close(release)
	h.silent(t)
	if _, spoke := h.health(); spoke || h.marked || !h.outageSince.IsZero() {
		t.Fatal("the old core's experiment leaked into the new session")
	}
}

func TestALateSystemStackAnswerForAnEarlierVerdictChangesNothing(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr, h.unbErr, h.askErr = errIOTimeout, errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	h.verdict(t)
	first := h.lastAt.Unix()
	h.connected(dialer.DialKindProxy, relay)
	h.verdict(t)
	h.systemStackReported(relay, first, true, 50, "")
	mustContain(t, h.verdict(t), "after the verdict was \"network\"", "the reading stands")
	if h.lastKind == witnessProcess {
		t.Fatal("a recovered outage must not be turned into the process's silence")
	}
	h.clock = h.clock.Add(bearerWitnessInterval)
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	h.verdict(t)
	h.systemStackReported(relay, first, false, 2000, "i/o timeout")
	mustContain(t, h.verdict(t), "not for the verdict in force")
	if health, _ := h.health(); health["systemStack"] != nil {
		t.Fatalf("an answer for another verdict was recorded: %v", health)
	}
}

func TestTheVerdictsKindStaysWithItsAddress(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr, h.unbErr, h.askErr = errIOTimeout, errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	h.verdict(t)
	h.observe(dialer.DialKindDirect, "tcp", "198.51.100.7:443", dialer.PhysicalDialStarted, nil)
	health, _ := h.health()
	if health["address"] != relay || health["dialKind"] != dialer.DialKindProxy {
		t.Fatalf("health %v, want the verdict's address and kind together", health)
	}
}

func TestTheResolverInstrumentResendsOnce(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go func() {
		buf := make([]byte, 1500)
		seen := 0
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			seen++
			if seen < 2 {
				continue
			}
			var q D.Msg
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			reply := new(D.Msg)
			reply.SetReply(&q)
			packed, _ := reply.Pack()
			_, _ = conn.WriteToUDP(packed, from)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), bearerWitnessTimeout)
	defer cancel()
	if err := askResolverOverUDP(ctx, conn.LocalAddr().String()); err != nil {
		t.Fatalf("the second copy was answered, got %v", err)
	}
}

func (h *witnessHarness) scheduledAfter(after time.Duration) []func() {
	h.mu.Lock()
	defer h.mu.Unlock()
	var runs []func()
	for _, call := range h.scheduled {
		if call.after == after {
			runs = append(runs, call.run)
		}
	}
	return runs
}

func (h *witnessHarness) networkVerdict(t *testing.T) {
	t.Helper()
	h.boundErr, h.unbErr, h.askErr = errIOTimeout, errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	h.verdict(t)
	h.waitActions(t, 1)
	if h.lastKind != witnessNetwork {
		t.Fatalf("setup: kind %q, want network", h.lastKind)
	}
}

func (h *witnessHarness) waitActions(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		h.mu.Lock()
		got := len(h.actions)
		h.mu.Unlock()
		if got >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d actions, want %d", got, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestTheWitnessFindingTheNetworkBackItselfIsTheRecovery(t *testing.T) {
	h := newWitnessHarness(t)
	h.networkVerdict(t)
	verdictAt := h.clock
	closedBefore, resetsBefore := len(h.closedAt), h.resets
	h.clock = h.clock.Add(bearerWitnessInterval)
	h.mu.Lock()
	h.boundErr = nil
	h.mu.Unlock()
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	mustContain(t, h.verdict(t), "the bound path carries")
	mustContain(t, h.verdict(t), "the network delivers again, 1m0s after it was found silent")
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.closedAt) != closedBefore+1 || !h.closedAt[closedBefore].Equal(verdictAt) {
		t.Fatalf("closed %v, want the flows opened before %v closed once more", h.closedAt, verdictAt)
	}
	if h.resets != resetsBefore+1 || h.checks != 1 {
		t.Fatalf("resets=%d (was %d) checks=%d, want one reset and one health-check round", h.resets, resetsBefore, h.checks)
	}
}

func TestABindingVerdictClosesTheFlowsBoundToTheDeadInterface(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr = errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	mustContain(t, h.verdict(t), "the binding is what is dead")
	h.waitActions(t, 1)
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.closedAt) != 1 || !h.closedAt[0].Equal(h.clock) || h.resets != 1 {
		t.Fatalf("closed=%v resets=%d, want the flows before the verdict closed and the network reset", h.closedAt, h.resets)
	}
	if len(h.actions) != 1 || !strings.Contains(h.actions[0], "bound to the dead interface are closed") {
		t.Fatalf("actions %v", h.actions)
	}
}

func TestANetworkVerdictIsActedOnThreeTimesWhileItLasts(t *testing.T) {
	h := newWitnessHarness(t)
	h.networkVerdict(t)
	h.mu.Lock()
	if len(h.actions) != 1 || h.resets != 1 {
		t.Fatalf("actions=%v resets=%d, want the first attempt at the verdict", h.actions, h.resets)
	}
	h.mu.Unlock()
	second, third := h.scheduledAfter(time.Second), h.scheduledAfter(5*time.Second)
	if len(second) != 1 || len(third) != 1 {
		t.Fatalf("scheduled %d at 1s and %d at 5s, want one each", len(second), len(third))
	}
	second[0]()
	third[0]()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.actions) != 3 || h.resets != 3 {
		t.Fatalf("actions=%d resets=%d, want three attempts", len(h.actions), h.resets)
	}
	mustContain(t, h.actions[2], "recovery attempt 3 of 3")
}

func TestARecoveryAttemptAfterTheOutageEndedDoesNothing(t *testing.T) {
	h := newWitnessHarness(t)
	h.networkVerdict(t)
	second := h.scheduledAfter(time.Second)
	h.connected(dialer.DialKindProxy, relay)
	h.verdict(t)
	h.mu.Lock()
	resets := h.resets
	h.mu.Unlock()
	second[0]()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.actions) != 1 || h.resets != resets {
		t.Fatalf("actions=%d resets=%d->%d, want a late attempt to do nothing", len(h.actions), resets, h.resets)
	}
}

func TestAHealthCheckRoundWithDeadNodesDoesNotRunTheWitness(t *testing.T) {
	h := newWitnessHarness(t)
	h.boundErr, h.unbErr, h.askErr = errIOTimeout, errIOTimeout, errIOTimeout
	for i := 0; i < 2*bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProbe, relay, errIOTimeout)
	}
	h.silent(t)
	if len(h.bound) != 0 {
		t.Fatalf("probes ran the experiment: %v", h.bound)
	}
}

func TestAProbeThatConnectsEndsTheOutage(t *testing.T) {
	h := newWitnessHarness(t)
	h.networkVerdict(t)
	h.connected(dialer.DialKindProbe, relay)
	mustContain(t, h.verdict(t), "the network delivers again")
	if h.marked {
		t.Fatal("the outage must end")
	}
}

func TestANewPathStartsTheWitnessOverAfterAGrace(t *testing.T) {
	h := newWitnessHarness(t)
	h.networkVerdict(t)
	h.pathChanged(2)
	mustContain(t, h.verdict(t), "the path changed", "the witness starts over on the new one")
	if h.marked || !h.outageSince.IsZero() || h.timeouts != 0 || h.checks != 0 {
		t.Fatalf("marked=%v outage=%v timeouts=%d checks=%d after the path change", h.marked, h.outageSince, h.timeouts, h.checks)
	}
	check := h.scheduledAfter(bearerWitnessPathCheckDelay)
	if len(check) != 1 {
		t.Fatalf("%d health-check rounds scheduled two seconds after the change, want one", len(check))
	}
	check[0]()
	if h.checks != 1 {
		t.Fatalf("checks=%d, want the round run when it comes due", h.checks)
	}
	bound := len(h.bound)
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	h.silent(t)
	if len(h.bound) != bound {
		t.Fatal("the witness ran inside the grace after a path change")
	}
	h.clock = h.clock.Add(bearerWitnessPathGrace)
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	h.verdict(t)
}

func TestAPathChangeToNoPathRunsNoHealthCheck(t *testing.T) {
	h := newWitnessHarness(t)
	h.pathChanged(0)
	if h.checks != 0 {
		t.Fatalf("checks=%d, want none with no path", h.checks)
	}
}

func TestAnExperimentFromTheOldPathIsDroppedOnTheNewOne(t *testing.T) {
	h := newWitnessHarness(t)
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	h.dialBound = func(context.Context, string) error {
		started <- struct{}{}
		<-release
		return errIOTimeout
	}
	h.unbErr, h.askErr = errIOTimeout, errIOTimeout
	for i := 0; i < bearerWitnessAfter; i++ {
		h.timeout(dialer.DialKindProxy, relay, errIOTimeout)
	}
	<-started
	h.pathChanged(2)
	close(release)
	h.silent(t)
	if h.marked || h.lastVerdict != "" {
		t.Fatal("the old path's experiment wrote into the new one")
	}
}

func TestStaleSetupResolversAreNotAsked(t *testing.T) {
	previousRead := readPhysicalResolvers
	readPhysicalResolvers = func(int32) []string { return nil }
	previous := systemDNSSubstitutes.Load()
	systemDNSSubstitutes.Store(&[]string{"192.168.1.1"})
	t.Cleanup(func() {
		readPhysicalResolvers = previousRead
		systemDNSSubstitutes.Store(previous)
		dns.SetSystemSubstitutesStale(false)
	})
	dns.SetSystemSubstitutesStale(false)
	if got := resolversOfPath(2); len(got) != 1 || got[0] != "192.168.1.1:53" {
		t.Fatalf("on the path the tunnel started on, got %v", got)
	}
	dns.SetSystemSubstitutesStale(true)
	if got := resolversOfPath(2); len(got) != 0 {
		t.Fatalf("stale resolvers were asked: %v", got)
	}
}

func TestTheResolverInstrumentDoesNotCountAServerFailure(t *testing.T) {
	for rcode, want := range map[int]bool{D.RcodeSuccess: true, D.RcodeNameError: true, D.RcodeServerFailure: false, D.RcodeRefused: false} {
		reply := new(D.Msg)
		reply.Rcode = rcode
		if got := answerSpeaks(reply) == nil; got != want {
			t.Fatalf("rcode %s counts=%v, want %v", D.RcodeToString[rcode], got, want)
		}
	}
}

func TestTheStallWindowIsFiveSeconds(t *testing.T) {
	if bearerWitnessStall != 5*time.Second {
		t.Fatalf("stall %s", bearerWitnessStall)
	}
}

func TestAHealthCheckRoundForASupersededPathDoesNotRun(t *testing.T) {
	h := newWitnessHarness(t)
	h.pathChanged(2)
	stale := h.scheduledAfter(bearerWitnessPathCheckDelay)
	h.pathChanged(5)
	stale[0]()
	if h.checks != 0 {
		t.Fatalf("checks=%d, want the superseded round dropped", h.checks)
	}
}
