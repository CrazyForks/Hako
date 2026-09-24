package dialer

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type observedDial struct {
	kind, network, address string
	event                  PhysicalDialEvent
	err                    error
}

type dialRecorder struct {
	mu   sync.Mutex
	seen []observedDial
}

func (r *dialRecorder) observe(kind, network, address string, event PhysicalDialEvent, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, observedDial{kind, network, address, event, err})
}

func (r *dialRecorder) events() []observedDial {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]observedDial(nil), r.seen...)
}

func installRecorder(t *testing.T) *dialRecorder {
	t.Helper()
	recorder := &dialRecorder{}
	SetPhysicalDialObserver(recorder.observe)
	t.Cleanup(func() { SetPhysicalDialObserver(nil) })
	return recorder
}

func TestAPhysicalTCPDialIsObservedFromSYNToAnswer(t *testing.T) {
	recorder := installRecorder(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(WithDialKind(context.Background(), DialKindProxy), 5*time.Second)
	defer cancel()
	conn, err := DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	seen := recorder.events()
	if len(seen) != 2 || seen[0].event != PhysicalDialStarted || seen[1].event != PhysicalDialSucceeded {
		t.Fatalf("a dial that connects is started then succeeded, got %+v", seen)
	}
	for _, event := range seen {
		if event.kind != DialKindProxy || event.address != listener.Addr().String() || !strings.HasPrefix(event.network, "tcp") {
			t.Fatalf("each event carries the kind, the network and the address the SYN went to, got %+v", event)
		}
	}
}

func TestARefusedPhysicalDialIsObservedAsFailedWithItsError(t *testing.T) {
	recorder := installRecorder(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := listener.Addr().String()
	_ = listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := DialContext(ctx, "tcp", closed); err == nil {
		t.Fatal("dialling a closed port must fail")
	}
	seen := recorder.events()
	if len(seen) != 2 || seen[0].event != PhysicalDialStarted || seen[1].event != PhysicalDialFailed || seen[1].err == nil {
		t.Fatalf("a refused dial is started then failed, with the error, got %+v", seen)
	}
	if seen[1].kind != "" {
		t.Fatalf("a dial nobody labelled has no kind, got %q", seen[1].kind)
	}
}

func TestAUDPDialIsNotObserved(t *testing.T) {
	recorder := installRecorder(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialContext(ctx, "udp", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if seen := recorder.events(); len(seen) != 0 {
		t.Fatalf("a UDP dial must not be observed, got %+v", seen)
	}
}
