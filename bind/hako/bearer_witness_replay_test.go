package hako


import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/component/dialer"
)

const replayDialTimeout = 5 * time.Second

type replayEventKind int

const (
	replayStarted replayEventKind = iota
	replaySucceeded
	replayFailed
	replayCoreStart
	replayPath
)

type replayEvent struct {
	at       time.Time
	seq      int
	kind     replayEventKind
	dialKind string
	network  string
	address  string
	err      error
	index    int32
	name     string
	connect  uint64
}

type replayLogged struct {
	at   time.Time
	what string
}

type replayLog struct {
	events    []replayEvent
	successes []time.Time
	failures  []replayFailure
	logged    []replayLogged
	first     time.Time
	last      time.Time
}

type replayFailure struct {
	started, ended time.Time
}

var (
	replayLine     = regexp.MustCompile(`time="([^"]+)" level=\w+ msg="(.*)"$`)
	replaySuccess  = regexp.MustCompile(`^\[TCP\] (\S+) --> (\S+) match .+ using (.+)$`)
	replayFailLine = regexp.MustCompile(`^\[TCP\] dial .+? \(match .+?\) (\S+) --> (\S+) error: (.*)$`)
	replayPathLine = regexp.MustCompile(`^\[Apple\] default path -> (\S*) \(index=(\d+)`)
	replayResolved = regexp.MustCompile("resolves `system` nameservers through ([^,]+(?:, [^,]+)*), read from")
	replayListed   = regexp.MustCompile(`dial tcp (\S+): ([^\\]+)`)
	replayWitness  = regexp.MustCompile(`^\[Apple\] bearer witness: (\d+ (?:direct )?(?:dials|connects) (?:in a row timed out|waiting unanswered))`)
)

var errReplayRefused = errors.New("replay: refused")

func replayIsTimeout(text string) bool {
	return strings.Contains(text, "deadline exceeded") || strings.Contains(text, "i/o timeout")
}

func replayAddress(host, port string) string {
	if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return netip.AddrPortFrom(addr, replayPort(port)).String()
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(host))
	sum := h.Sum32()
	return fmt.Sprintf("100.%d.%d.%d:%d", 64+(sum>>16)&63, (sum>>8)&255, sum&255, replayPort(port))
}

func replayPort(port string) uint16 {
	value, err := strconv.Atoi(port)
	if err != nil || value <= 0 || value > 65535 {
		return 443
	}
	return uint16(value)
}

func replaySplit(hostport string) (string, string) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, "443"
	}
	return host, port
}

func parseReplayLog(t *testing.T, path, mode string) replayLog {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer file.Close()

	type line struct {
		at  time.Time
		msg string
	}
	var lines []line
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1<<20), 16<<20)
	for scanner.Scan() {
		match := replayLine.FindStringSubmatch(scanner.Text())
		if match == nil {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, match[1])
		if err != nil {
			continue
		}
		lines = append(lines, line{at, match[2]})
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	counts := map[string]int{}
	for _, l := range lines {
		match := replayFailLine.FindStringSubmatch(l.msg)
		if match == nil {
			continue
		}
		host, rest := replayTarget(match[2], match[3])
		if listed := replayListed.FindAllStringSubmatch(rest, -1); len(listed) > counts[host] {
			counts[host] = len(listed)
		}
	}

	var out replayLog
	resolvers := []string{"198.51.100.1:53", "198.51.100.2:53", "198.51.100.3:53"}
	seq := 0
	var connects uint64
	add := func(e replayEvent) {
		e.seq = seq
		seq++
		out.events = append(out.events, e)
	}
	for _, l := range lines {
		if out.first.IsZero() || l.at.Before(out.first) {
			out.first = l.at
		}
		if l.at.After(out.last) {
			out.last = l.at
		}
		switch {
		case strings.HasPrefix(l.msg, "[Memory] GC pacing armed"):
			add(replayEvent{at: l.at, kind: replayCoreStart})
		case replayPathLine.MatchString(l.msg):
			match := replayPathLine.FindStringSubmatch(l.msg)
			index, _ := strconv.Atoi(match[2])
			add(replayEvent{at: l.at, kind: replayPath, name: match[1], index: int32(index)})
		case replayResolved.MatchString(l.msg):
			var found []string
			for _, endpoint := range strings.Split(replayResolved.FindStringSubmatch(l.msg)[1], ", ") {
				if _, err := netip.ParseAddrPort(endpoint); err == nil {
					found = append(found, endpoint)
				}
			}
			if len(found) > 0 {
				resolvers = found
			}
		case replayWitness.MatchString(l.msg):
			out.logged = append(out.logged, replayLogged{l.at, replayWitness.FindStringSubmatch(l.msg)[1]})
		case replaySuccess.MatchString(l.msg):
			match := replaySuccess.FindStringSubmatch(l.msg)
			using := match[3]
			node := using
			if i := strings.LastIndex(using, "["); i >= 0 {
				node = strings.TrimRight(using[i+1:], "]")
			}
			var kind, address string
			switch node {
			case "DIRECT":
				host, port := replaySplit(match[2])
				kind, address = dialer.DialKindDirect, replayAddress(host, port)
			case "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE":
				continue
			default:
				kind, address = dialer.DialKindProxy, replayAddress("node:"+node, "443")
			}
			connects++
			add(replayEvent{at: l.at.Add(-50 * time.Millisecond), kind: replayStarted, dialKind: kind, network: "tcp", address: address, connect: connects})
			add(replayEvent{at: l.at, kind: replaySucceeded, dialKind: kind, network: "tcp", address: address, connect: connects})
			out.successes = append(out.successes, l.at)
		case replayFailLine.MatchString(l.msg):
			match := replayFailLine.FindStringSubmatch(l.msg)
			host, rest := replayTarget(match[2], match[3])
			kind := dialer.DialKindDirect
			if strings.Contains(match[3], " connect error: ") {
				kind = dialer.DialKindProxy
			}
			if strings.Contains(rest, "dns resolve failed") {
				if !replayIsTimeout(rest) {
					continue
				}
				for _, endpoint := range resolvers {
					add(replayEvent{at: l.at.Add(-replayDialTimeout), kind: replayStarted, dialKind: dialer.DialKindResolver, network: "udp", address: endpoint})
					add(replayEvent{at: l.at, kind: replayFailed, dialKind: dialer.DialKindResolver, network: "udp", address: endpoint, err: context.DeadlineExceeded})
				}
				out.failures = append(out.failures, replayFailure{l.at.Add(-replayDialTimeout), l.at})
				continue
			}
			type attempt struct {
				address string
				err     error
			}
			var attempts []attempt
			for _, listed := range replayListed.FindAllStringSubmatch(rest, -1) {
				h, p := replaySplit(listed[1])
				err := errReplayRefused
				if replayIsTimeout(listed[2]) {
					err = context.DeadlineExceeded
				}
				attempts = append(attempts, attempt{replayAddress(h, p), err})
			}
			if len(attempts) == 0 {
				err := errReplayRefused
				if replayIsTimeout(rest) {
					err = context.DeadlineExceeded
				}
				_, port := replaySplit(replayTargetHostPort(match[2], match[3]))
				n := max(counts[host], 1)
				for i := 0; i < n; i++ {
					name := host
					if i > 0 {
						name = fmt.Sprintf("%s#%d", host, i)
					}
					attempts = append(attempts, attempt{replayAddress(name, port), err})
				}
			}
			connects++
			timedOut := false
			for i, a := range attempts {
				started := l.at.Add(-replayDialTimeout + time.Millisecond)
				if a.err != context.DeadlineExceeded {
					started = l.at.Add(-50 * time.Millisecond)
				} else if mode == "serial" && i > 0 {
					started = l.at
				}
				if a.err == context.DeadlineExceeded {
					timedOut = true
				}
				add(replayEvent{at: started, kind: replayStarted, dialKind: kind, network: "tcp", address: a.address, connect: connects})
				add(replayEvent{at: l.at, kind: replayFailed, dialKind: kind, network: "tcp", address: a.address, err: a.err, connect: connects})
			}
			if timedOut {
				out.failures = append(out.failures, replayFailure{l.at.Add(-replayDialTimeout), l.at})
			}
		}
	}
	sort.SliceStable(out.events, func(i, j int) bool {
		if !out.events[i].at.Equal(out.events[j].at) {
			return out.events[i].at.Before(out.events[j].at)
		}
		return out.events[i].seq < out.events[j].seq
	})
	sort.Slice(out.successes, func(i, j int) bool { return out.successes[i].Before(out.successes[j]) })
	sort.Slice(out.failures, func(i, j int) bool { return out.failures[i].started.Before(out.failures[j].started) })
	return out
}

func replayTarget(destination, errText string) (string, string) {
	if i := strings.Index(errText, " connect error: "); i > 0 {
		host, _ := replaySplit(errText[:i])
		return host, errText[i+len(" connect error: "):]
	}
	host, _ := replaySplit(destination)
	return host, errText
}

func replayTargetHostPort(destination, errText string) string {
	if i := strings.Index(errText, " connect error: "); i > 0 {
		return errText[:i]
	}
	return destination
}

type replayTimer struct {
	at  time.Time
	seq int
	run func()
}

type replaySpoken struct {
	at   time.Time
	kind string
	text string
}

type replayBench struct {
	mu        sync.Mutex
	clock     time.Time
	timers    []replayTimer
	timerSeq  int
	spoken    []replaySpoken
	successes []time.Time
	witness   *bearerWitness
	cellular bool
}

func (b *replayBench) now() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.clock
}

func (b *replayBench) carries() error {
	at := b.now()
	i := sort.Search(len(b.successes), func(i int) bool { return !b.successes[i].Before(at) })
	if i < len(b.successes) && b.successes[i].Sub(at) <= bearerWitnessTimeout {
		return nil
	}
	return context.DeadlineExceeded
}

func replayVerdictKind(text string) string {
	switch {
	case strings.Contains(text, "the bound path carries"):
		return witnessCarries
	case strings.Contains(text, "the binding is what is dead"):
		return witnessBinding
	case strings.Contains(text, "is unreachable, not the link"):
		return witnessDestination
	case strings.Contains(text, "the network itself is not delivering"):
		return witnessNetwork
	case strings.Contains(text, "does not guess"):
		return witnessUnknown
	}
	return ""
}

func newReplayBench(successes []time.Time) *replayBench {
	b := &replayBench{successes: successes}
	b.witness = &bearerWitness{
		now:         b.now,
		timedOut:    map[uint64]struct{}{},
		pending:     map[uint64]int{},
		dialBound:   func(context.Context, string) error { return b.carries() },
		dialUnbound: func(context.Context, string) error { return b.carries() },
		askResolver: func(context.Context, string) error { return b.carries() },
		pathResolvers: func(int32) []string {
			return []string{"198.51.100.1:53"}
		},
		closeFlowsBefore: func(time.Time) int { return 0 },
		schedule: func(after time.Duration, run func()) {
			b.mu.Lock()
			defer b.mu.Unlock()
			b.timerSeq++
			b.timers = append(b.timers, replayTimer{b.clock.Add(after), b.timerSeq, run})
		},
		report: func(text string) {
			b.mu.Lock()
			defer b.mu.Unlock()
			if kind := replayVerdictKind(text); kind != "" {
				b.spoken = append(b.spoken, replaySpoken{b.clock, kind, text})
			}
		},
		setSilent:          func(bool) {},
		resetNetwork:       func() {},
		checkEveryProvider: func() {},
		pathIsCellular: func() bool {
			b.mu.Lock()
			defer b.mu.Unlock()
			return b.cellular
		},
	}
	return b
}

func (b *replayBench) settle() {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b.witness.mu.Lock()
		running := b.witness.running
		b.witness.mu.Unlock()
		if !running {
			return
		}
		time.Sleep(20 * time.Microsecond)
	}
}

func (b *replayBench) advance(to time.Time) {
	for {
		b.mu.Lock()
		if len(b.timers) == 0 {
			b.clock = maxTime(b.clock, to)
			b.mu.Unlock()
			return
		}
		sort.Slice(b.timers, func(i, j int) bool {
			if !b.timers[i].at.Equal(b.timers[j].at) {
				return b.timers[i].at.Before(b.timers[j].at)
			}
			return b.timers[i].seq < b.timers[j].seq
		})
		next := b.timers[0]
		if !next.at.Before(to) {
			b.clock = maxTime(b.clock, to)
			b.mu.Unlock()
			return
		}
		b.timers = b.timers[1:]
		b.clock = maxTime(b.clock, next.at)
		b.mu.Unlock()
		next.run()
		b.settle()
	}
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func (b *replayBench) run(log replayLog) {
	w := b.witness
	previous := publishedInterfaceIndex.Load()
	defer func() {
		publishedInterfaceIndex.Store(previous)
		clearBindingSuspension()
	}()
	publishedInterfaceIndex.Store(0)
	b.clock = log.first
	pathName, pathKnown := "", false
	for _, e := range log.events {
		b.advance(e.at)
		switch e.kind {
		case replayCoreStart:
			publishedInterfaceIndex.Store(0)
			clearBindingSuspension()
			w.reset()
			pathName, pathKnown = "", false
		case replayPath:
			publishedInterfaceIndex.Store(e.index)
			b.mu.Lock()
			b.cellular = strings.HasPrefix(e.name, "pdp_ip")
			b.mu.Unlock()
			if pathKnown && e.name != pathName {
				index := e.index
				w.schedule(pathSettleDelay, func() { w.pathChanged(index) })
			}
			pathName, pathKnown = e.name, true
		case replayStarted:
			w.observe(e.dialKind, e.network, e.address, e.connect, dialer.PhysicalDialStarted, nil)
		case replaySucceeded:
			w.observe(e.dialKind, e.network, e.address, e.connect, dialer.PhysicalDialSucceeded, nil)
		case replayFailed:
			w.observe(e.dialKind, e.network, e.address, e.connect, dialer.PhysicalDialFailed, e.err)
		}
		b.settle()
	}
	b.advance(log.last.Add(time.Minute))
}

type replayOutage struct {
	start, end time.Time
	failures   int
}

const replayOutageGap = 5 * time.Second

func replayOutages(log replayLog) []replayOutage {
	var outages []replayOutage
	previous := log.first
	next := func(after time.Time) time.Time {
		i := sort.Search(len(log.successes), func(i int) bool { return log.successes[i].After(after) })
		if i == len(log.successes) {
			return log.last
		}
		return log.successes[i]
	}
	for i := 0; i < len(log.failures); {
		f := log.failures[i]
		j := sort.Search(len(log.successes), func(k int) bool { return !log.successes[k].Before(f.started) })
		if j > 0 {
			previous = log.successes[j-1]
		}
		end := next(f.started)
		count := 0
		for i < len(log.failures) && log.failures[i].started.Before(end) {
			count++
			i++
		}
		start := maxTime(f.started, previous)
		if end.Sub(start) >= replayOutageGap && count >= 3 {
			outages = append(outages, replayOutage{start, end, count})
		}
	}
	return outages
}

func TestBearerWitnessReplay(t *testing.T) {
	paths := os.Getenv("HAKO_WITNESS_REPLAY")
	if paths == "" {
		t.Skip("HAKO_WITNESS_REPLAY names no exported logs to replay")
	}
	var report strings.Builder
	for _, path := range strings.Split(paths, ",") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		for _, mode := range []string{"parallel", "serial"} {
			log := parseReplayLog(t, path, mode)
			bench := newReplayBench(log.successes)
			bench.run(log)
			writeReplayReport(&report, path, mode, log, bench.spoken)
		}
	}
	if out := os.Getenv("HAKO_WITNESS_REPLAY_OUT"); out != "" {
		if err := os.WriteFile(out, []byte(report.String()), 0o600); err != nil {
			t.Fatalf("write %s: %v", out, err)
		}
		return
	}
	t.Log("\n" + report.String())
}

func writeReplayReport(report *strings.Builder, path, mode string, log replayLog, spoken []replaySpoken) {
	local := func(at time.Time) string { return at.In(time.FixedZone("CST", 8*3600)).Format("01-02 15:04:05.0") }
	name := path
	if i := strings.LastIndex(path, "/"); i >= 0 {
		name = path[i+1:]
	}
	fmt.Fprintf(report, "=== %s [%s] %s .. %s\n", name, mode, local(log.first), local(log.last))

	outages := replayOutages(log)
	claimed := make([]bool, len(spoken))
	detected := 0
	for _, o := range outages {
		first := -1
		for i, s := range spoken {
			if !s.at.Before(o.start) && !s.at.After(o.end.Add(bearerWitnessTimeout)) {
				claimed[i] = true
				if first < 0 {
					first = i
				}
			}
		}
		line := fmt.Sprintf("outage %s  %5.1fs  %3d timed-out connects", local(o.start), o.end.Sub(o.start).Seconds(), o.failures)
		if first >= 0 {
			detected++
			trigger := spoken[first].text
			if i := strings.Index(trigger, ", the last"); i > 0 {
				trigger = strings.TrimPrefix(trigger[:i], "[Apple] bearer witness: ")
			}
			line += fmt.Sprintf("  -> witness at +%.1fs (%s; %s)", spoken[first].at.Sub(o.start).Seconds(), spoken[first].kind, trigger)
		} else {
			line += "  -> witness silent"
		}
		fmt.Fprintln(report, line)
	}
	outside := 0
	for i, s := range spoken {
		if claimed[i] {
			continue
		}
		outside++
		fmt.Fprintf(report, "outside  %s  %s\n", local(s.at), s.kind)
	}
	for _, l := range log.logged {
		fmt.Fprintf(report, "device   %s  %s\n", local(l.at), l.what)
	}
	fmt.Fprintf(report, "summary [%s] outages=%d detected=%d spoke=%d outside-outages=%d device-spoke=%d\n\n",
		mode, len(outages), detected, len(spoken), outside, len(log.logged))
}
