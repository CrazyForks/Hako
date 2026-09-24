package hako

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TokenPLS/Hako/component/dialer"
	"github.com/TokenPLS/Hako/component/pause"
	"github.com/TokenPLS/Hako/dns"
	"github.com/TokenPLS/Hako/log"
	"github.com/TokenPLS/Hako/tunnel/statistic"
	D "github.com/miekg/dns"
)


const bearerWitnessPending = 5

const bearerWitnessStall = 5 * time.Second

const bearerWitnessPathGrace = 8 * time.Second

var bearerWitnessRetries = []time.Duration{0, time.Second, 5 * time.Second}

const bearerWitnessAfter = 5

const bearerWitnessInterval = time.Minute

const bearerWitnessTimeout = 2 * time.Second

const (
	witnessCarries     = "carries"
	witnessBinding     = "binding"
	witnessDestination = "destination"
	witnessNetwork     = "network"
	witnessUnknown = "unknown"
	witnessProcess = "process"
)

type bearerWitness struct {
	mu          sync.Mutex
	inFlight    int
	oldestStart time.Time
	lastSuccess time.Time
	timeouts    int
	lastRun     time.Time
	running     bool
	lastAddress  string
	lastDialKind string
	lastSilentAddress string
	lastSilentKind    string
	lastVerdict  string
	lastKind     string
	lastResolver string
	lastAt       time.Time
	verdictAddress string
	lastSystem string
	outageSince time.Time
	session uint64
	verdictDialKind string
	graceUntil time.Time
	stallArmed bool

	now              func() time.Time
	dialBound        func(ctx context.Context, address string) error
	dialUnbound      func(ctx context.Context, address string) error
	askResolver      func(ctx context.Context, endpoint string) error
	pathResolvers    func(index int32) []string
	closeFlowsBefore func(at time.Time) int
	schedule         func(after time.Duration, run func())
	report           func(verdict string)
	setSilent func(bool)
	resetNetwork func()
	checkEveryProvider func()
}

const witnessDialKind = "witness"

var witness = newBearerWitness()

func newBearerWitness() *bearerWitness {
	return &bearerWitness{
		now: time.Now,
		dialBound: func(ctx context.Context, address string) error {
			conn, err := dialer.DialContext(dialer.WithDialKind(ctx, witnessDialKind), "tcp", address)
			if err == nil {
				_ = conn.Close()
			}
			return err
		},
		dialUnbound: func(ctx context.Context, address string) error {
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
			if err == nil {
				_ = conn.Close()
			}
			return err
		},
		askResolver:      askResolverOverUDP,
		pathResolvers:    resolversOfPath,
		closeFlowsBefore: closeTrackedFlowsStartedBefore,
		schedule:         func(after time.Duration, run func()) { time.AfterFunc(after, run) },
		report:           func(verdict string) { log.Warnln("%s", verdict) },
		setSilent: pause.SetBearerSilent,
		resetNetwork: func() {
			resetResolverConnection()
			resetOutboundSessions()
		},
		checkEveryProvider: checkEveryProviderOnce,
	}
}

func init() {
	dialer.SetPhysicalDialObserver(witness.observe)
}

func (w *bearerWitness) observe(kind, network, address string, event dialer.PhysicalDialEvent, err error) {
	question := kind == dialer.DialKindResolver
	if (!question && (len(network) < 3 || network[:3] != "tcp")) || kind == witnessDialKind {
		return
	}
	probe := kind == dialer.DialKindProbe
	if probe && event != dialer.PhysicalDialSucceeded {
		return
	}
	destination, parseErr := netip.ParseAddrPort(address)
	if parseErr != nil || destination.Addr().IsLoopback() || destination.Addr().IsUnspecified() {
		return
	}
	now := w.now()

	w.mu.Lock()
	switch event {
	case dialer.PhysicalDialStarted:
		w.inFlight++
		if w.inFlight == 1 {
			w.oldestStart = now
		}
		w.noteSilentLocked(question, address, kind)
		if w.inFlight >= bearerWitnessPending && !w.stallArmed {
			w.stallArmed = true
			session := w.session
			w.schedule(bearerWitnessStall, func() { w.stallWindowClosed(session) })
		}
	case dialer.PhysicalDialSucceeded:
		if !probe {
			w.inFlight = max(0, w.inFlight-1)
		}
		w.lastSuccess = now
		w.timeouts = 0
		w.oldestStart = now
		outageSince := w.outageSince
		w.setOutageLocked(time.Time{})
		w.mu.Unlock()
		if !outageSince.IsZero() {
			go w.recover(outageSince, now)
		}
		return
	case dialer.PhysicalDialFailed:
		w.inFlight = max(0, w.inFlight-1)
		if w.inFlight == 0 {
			w.oldestStart = now
		}
		if !isDialTimeout(err) {
			w.mu.Unlock()
			return
		}
		w.timeouts++
		w.noteSilentLocked(question, address, kind)
	}
	w.considerLocked(now, event == dialer.PhysicalDialFailed)
}

func (w *bearerWitness) noteSilentLocked(question bool, address, kind string) {
	w.lastSilentAddress, w.lastSilentKind = address, kind
	if !question || w.lastAddress == "" {
		w.lastAddress, w.lastDialKind = address, kind
	}
}

func (w *bearerWitness) stallWindowClosed(session uint64) {
	w.mu.Lock()
	if session != w.session {
		w.mu.Unlock()
		return
	}
	w.stallArmed = false
	w.considerLocked(w.now(), false)
}

func (w *bearerWitness) setOutageLocked(since time.Time) {
	w.outageSince = since
	w.setSilent(!since.IsZero())
}

func (w *bearerWitness) considerLocked(now time.Time, failed bool) {
	stalled := w.inFlight >= bearerWitnessPending &&
		now.Sub(w.oldestStart) >= bearerWitnessStall &&
		(w.lastSuccess.IsZero() || now.Sub(w.lastSuccess) >= bearerWitnessStall)
	timedOut := failed && w.timeouts >= bearerWitnessAfter
	due := (stalled || timedOut) && !w.running &&
		(w.lastRun.IsZero() || now.Sub(w.lastRun) >= bearerWitnessInterval) &&
		!now.Before(w.graceUntil)
	if due {
		w.running = true
		w.lastRun = now
	}
	pending, timeouts := w.inFlight, w.timeouts
	target, targetKind := w.lastAddress, w.lastDialKind
	silent, silentKind := w.lastSilentAddress, w.lastSilentKind
	session := w.session
	w.mu.Unlock()
	if !due {
		return
	}
	if publishedInterfaceIndex.Load() == 0 || pause.IsNetworkPaused() {
		w.mu.Lock()
		if session == w.session {
			w.running = false
			w.lastRun = time.Time{}
		}
		w.mu.Unlock()
		return
	}
	go w.run(session, target, targetKind, silent, silentKind, pending, timeouts)
}

func (w *bearerWitness) run(session uint64, address, dialKind, silent, silentKind string, pending, timeouts int) {
	defer func() {
		w.mu.Lock()
		if session == w.session {
			w.running = false
		}
		w.mu.Unlock()
	}()
	index := publishedInterfaceIndex.Load()
	started := w.now()
	resolvers := w.pathResolvers(index)

	results := make(chan witnessResult, 2+len(resolvers))
	go func() { results <- w.dial("bound", w.dialBound, address) }()
	go func() { results <- w.dial("unbound", w.dialUnbound, address) }()
	for _, endpoint := range resolvers {
		endpoint := endpoint
		go func() { results <- w.dial(endpoint, w.askResolver, endpoint) }()
	}
	var bound, unbound, resolver witnessResult
	for i := 0; i < cap(results); i++ {
		result := <-results
		switch result.side {
		case "unbound":
			unbound = result
			if result.err == nil && (bound.side == "" || bound.err != nil) && w.inSession(session) {
				suspendBinding(index)
			}
		case "bound":
			bound = result
			if result.err == nil && w.inSession(session) {
				clearBindingSuspension()
			}
		default:
			if resolver.side == "" || (resolver.err != nil && result.err == nil) {
				resolver = result
			}
		}
	}

	var kind, reading string
	switch {
	case bound.err == nil:
		kind = witnessCarries
		reading = "the bound path carries; the silence was the network's, and it has passed"
	case unbound.err == nil:
		kind = witnessBinding
		reading = "the interface this process binds its sockets to is not carrying traffic while the system's own route is: the binding is what is dead, not the network; outbound sockets dial unbound from here until the path next changes"
	case resolver.side != "" && resolver.err == nil:
		kind = witnessDestination
		reading = fmt.Sprintf("the network delivers -- its resolver at %s answered in %s -- and %s does not: %s is unreachable, not the link",
			resolver.side, resolver.took.Round(time.Millisecond), address, nameDestination(dialKind, address))
	case resolver.side == "":
		kind = witnessUnknown
		reading = "neither path carries, and this path lists no resolver to ask: the witness cannot tell the network's silence from the destination's, and does not guess"
	default:
		kind = witnessNetwork
		reading = fmt.Sprintf("neither path carries and the path's resolver at %s is silent too: the network itself is not delivering, and there is nothing this process could bind to instead", resolver.side)
	}
	what := fmt.Sprintf("%d dials waiting unanswered", pending)
	if timeouts >= bearerWitnessAfter {
		what = fmt.Sprintf("%d dials in a row timed out", timeouts)
	}
	last := "to " + describeDestination(dialKind, address)
	if silentKind == dialer.DialKindResolver {
		last = "a question to the resolver at " + silent
	}
	verdict := fmt.Sprintf("[Apple] bearer witness: %s, the last %s, on interface index %d; dialled again bound: %s in %s; unbound: %s in %s -- %s",
		what, last, index, bound, bound.took.Round(time.Millisecond), unbound, unbound.took.Round(time.Millisecond), reading)

	w.mu.Lock()
	if session != w.session {
		w.mu.Unlock()
		return
	}
	w.lastVerdict, w.lastKind, w.lastResolver, w.lastAt = verdict, kind, resolver.side, started
	w.verdictAddress, w.verdictDialKind, w.lastSystem = address, dialKind, ""
	previous := w.outageSince
	outageBegins := false
	switch kind {
	case witnessNetwork:
		if previous.IsZero() {
			w.setOutageLocked(started)
			outageBegins = true
		}
	case witnessUnknown:
	default:
		w.setOutageLocked(time.Time{})
	}
	w.mu.Unlock()
	w.report(verdict)
	switch {
	case !previous.IsZero() && kind != witnessNetwork && kind != witnessUnknown:
		w.recover(previous, started)
	case kind == witnessBinding:
		closed := w.closeFlowsBefore(started)
		w.resetNetwork()
		w.report(fmt.Sprintf("[Apple] bearer witness: %d connections bound to the dead interface are closed so their apps reconnect unbound", closed))
	case outageBegins:
		w.beginRecoveryAttempts(session, started)
	}
}

func (w *bearerWitness) systemStackReported(address string, atUnix int64, connected bool, tookMillis int64, failure string) {
	took := (time.Duration(tookMillis) * time.Millisecond).Round(time.Millisecond)
	outcome := fmt.Sprintf("connected in %s", took)
	if !connected {
		if failure == "" {
			failure = "did not connect"
		}
		outcome = fmt.Sprintf("%s in %s", failure, took)
	}

	w.mu.Lock()
	var line string
	switch {
	case w.lastVerdict == "" || address != w.verdictAddress || atUnix != w.lastAt.Unix():
		what := fmt.Sprintf("connected to %s in %s", address, took)
		if !connected {
			what = fmt.Sprintf("could not connect to %s: %s", address, outcome)
		}
		why := "and the witness has not spoken"
		if w.lastVerdict != "" {
			why = fmt.Sprintf("not for the verdict in force (%s at %d)", w.verdictAddress, w.lastAt.Unix())
		}
		line = fmt.Sprintf("[Apple] bearer witness: the system's own stack %s -- %s; the reading stands", what, why)
	case w.lastKind != witnessNetwork || w.outageSince.IsZero():
		line = fmt.Sprintf("[Apple] bearer witness: the system's own stack %s to %s after the verdict was %q; the reading stands",
			outcome, address, w.lastKind)
	case connected:
		w.lastSystem = outcome
		w.lastKind = witnessProcess
		line = fmt.Sprintf("[Apple] bearer witness: the system's own stack connected to %s in %s while this process's sockets could not: the silence is this process's, not the bearer's",
			address, took)
	default:
		w.lastSystem = outcome
		line = fmt.Sprintf("[Apple] bearer witness: the system's own stack could not connect to %s either: %s -- the bearer is silent for every stack on this device",
			address, outcome)
	}
	w.mu.Unlock()
	w.report(line)
}

func ReportSystemStackProbe(address string, atUnix int64, connected bool, tookMillis int64, failure string) {
	witness.systemStackReported(address, atUnix, connected, tookMillis, failure)
}

func (w *bearerWitness) recover(outageSince, now time.Time) {
	closed := w.closeFlowsBefore(outageSince)
	w.resetNetwork()
	w.checkEveryProvider()
	w.report(fmt.Sprintf("[Apple] bearer witness: the network delivers again, %s after it was found silent; %d connections opened before that verdict are closed so their apps reconnect through a path that carries",
		now.Sub(outageSince).Round(time.Second), closed))
}

func (w *bearerWitness) beginRecoveryAttempts(session uint64, since time.Time) {
	for attempt, after := range bearerWitnessRetries {
		attempt := attempt + 1
		run := func() { w.recoveryAttempt(session, since, attempt) }
		if after == 0 {
			run()
			continue
		}
		w.schedule(after, run)
	}
}

func (w *bearerWitness) recoveryAttempt(session uint64, since time.Time, attempt int) {
	w.mu.Lock()
	current := session == w.session && w.outageSince.Equal(since)
	w.mu.Unlock()
	if !current {
		return
	}
	closed := w.closeFlowsBefore(since)
	w.resetNetwork()
	w.report(fmt.Sprintf("[Apple] bearer witness: recovery attempt %d of %d during the network's silence: %d flows opened before it closed, resolver connections and outbound sessions reset",
		attempt, len(bearerWitnessRetries), closed))
}

func (w *bearerWitness) pathChanged(index int32) {
	w.mu.Lock()
	outage := w.outageSince
	w.session++
	w.inFlight, w.timeouts, w.running, w.stallArmed = 0, 0, false, false
	w.oldestStart, w.lastRun = time.Time{}, time.Time{}
	w.graceUntil = w.now().Add(bearerWitnessPathGrace)
	w.setOutageLocked(time.Time{})
	w.mu.Unlock()
	if !outage.IsZero() {
		w.report(fmt.Sprintf("[Apple] bearer witness: the path changed %s after the network was found silent; the witness starts over on the new one",
			w.now().Sub(outage).Round(time.Second)))
	}
	if index != 0 {
		w.mu.Lock()
		session := w.session
		w.mu.Unlock()
		w.schedule(bearerWitnessPathCheckDelay, func() {
			if w.inSession(session) {
				w.checkEveryProvider()
			}
		})
	}
}

const bearerWitnessPathCheckDelay = 2 * time.Second

func (w *bearerWitness) inSession(session uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return session == w.session
}

func (w *bearerWitness) reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.session++
	w.inFlight, w.timeouts, w.running, w.stallArmed = 0, 0, false, false
	w.oldestStart, w.lastSuccess, w.lastRun, w.lastAt = time.Time{}, time.Time{}, time.Time{}, time.Time{}
	w.lastAddress, w.lastDialKind, w.lastSilentAddress, w.lastSilentKind = "", "", "", ""
	w.lastVerdict, w.lastKind, w.lastResolver, w.verdictAddress, w.verdictDialKind, w.lastSystem = "", "", "", "", "", ""
	w.graceUntil = time.Time{}
	w.setOutageLocked(time.Time{})
}

func nameDestination(dialKind, address string) string {
	if dialKind == dialer.DialKindProxy {
		return "the proxy server at " + address
	}
	return address
}

func describeDestination(dialKind, address string) string {
	switch dialKind {
	case dialer.DialKindProxy:
		return "a proxy server at " + address
	default:
		return address
	}
}

type witnessResult struct {
	side string
	err  error
	took time.Duration
}

func (r witnessResult) String() string {
	if r.err == nil {
		return "connected"
	}
	return r.err.Error()
}

func (w *bearerWitness) dial(side string, dialFn func(context.Context, string) error, address string) witnessResult {
	ctx, cancel := context.WithTimeout(context.Background(), bearerWitnessTimeout)
	defer cancel()
	started := w.now()
	err := dialFn(ctx, address)
	return witnessResult{side: side, err: err, took: w.now().Sub(started)}
}

func askResolverOverUDP(ctx context.Context, endpoint string) error {
	conn, err := dialer.DialContext(ctx, "udp", endpoint)
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	question := new(D.Msg)
	question.SetQuestion(".", D.TypeNS)
	dnsConn := &D.Conn{Conn: conn}
	if err := dnsConn.WriteMsg(question); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) > witnessResolverResend {
		_ = conn.SetReadDeadline(time.Now().Add(witnessResolverResend))
		var reply *D.Msg
		if reply, err = dnsConn.ReadMsg(); err == nil {
			return answerSpeaks(reply)
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			return err
		}
		_ = dnsConn.WriteMsg(question)
		_ = conn.SetReadDeadline(deadline)
	}
	reply, err := dnsConn.ReadMsg()
	if err != nil {
		return err
	}
	return answerSpeaks(reply)
}

var errAnswerSaysNothing = errors.New("the resolver answered, but not with an answer")

func answerSpeaks(reply *D.Msg) error {
	if reply.Rcode == D.RcodeSuccess || reply.Rcode == D.RcodeNameError {
		return nil
	}
	return fmt.Errorf("%w: %s", errAnswerSaysNothing, D.RcodeToString[reply.Rcode])
}

const witnessResolverResend = time.Second

func resolversOfPath(index int32) []string {
	lines := readPhysicalResolvers(index)
	if len(lines) == 0 && !dns.SystemSubstitutesStale() {
		lines = systemDNSServerSubstitutes()
	}
	endpoints := make([]string, 0, len(lines))
	for _, line := range lines {
		if endpoint := resolverEndpoint(line); endpoint != "" {
			endpoints = append(endpoints, endpoint)
		}
		if len(endpoints) == 3 {
			break
		}
	}
	return endpoints
}

func resolverEndpoint(line string) string {
	if endpoint, err := netip.ParseAddrPort(line); err == nil {
		return endpoint.String()
	}
	if addr, err := netip.ParseAddr(line); err == nil {
		return netip.AddrPortFrom(addr, 53).String()
	}
	return ""
}

func closeTrackedFlowsStartedBefore(at time.Time) int {
	closed := 0
	statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
		if info := tracker.Info(); info != nil && info.Start.Before(at) {
			_ = tracker.Close()
			closed++
		}
		return true
	})
	return closed
}

func (w *bearerWitness) health() (map[string]any, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.lastVerdict == "" {
		return nil, false
	}
	health := map[string]any{
		"verdict":          w.lastVerdict,
		"kind":             w.lastKind,
		"address":          w.verdictAddress,
		"dialKind":         w.verdictDialKind,
		"atUnix":           w.lastAt.Unix(),
		"bindingSuspended": bindingSuspendedForIndex.Load() != 0,
	}
	if w.lastResolver != "" {
		health["resolver"] = w.lastResolver
	}
	if w.lastSystem != "" {
		health["systemStack"] = w.lastSystem
	}
	return health, true
}

func isDialTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

var bindingSuspendedForIndex atomic.Int32

func suspendBinding(index int32) { bindingSuspendedForIndex.Store(index) }

func clearBindingSuspension() { bindingSuspendedForIndex.Store(0) }

func bindingSuspended(index int32) bool {
	suspended := bindingSuspendedForIndex.Load()
	return suspended != 0 && suspended == index
}
