package hako

import (
	"net"
	"syscall"
	"testing"

	"github.com/TokenPLS/Hako/component/dialer"
)

type hookPlatform struct {
	recordingPlatform
	enabled    bool
	gotFd      int32
	callCount  int
	controlErr error
}

func (p *hookPlatform) UsePlatformAutoDetectInterfaceControl() bool { return p.enabled }
func (p *hookPlatform) AutoDetectInterfaceControl(fd int32) error {
	p.callCount++
	p.gotFd = fd
	return p.controlErr
}

func TestInstallSocketHook(t *testing.T) {
	orig := dialer.DefaultSocketHook
	origTransform := dialer.DefaultAddressTransform
	t.Cleanup(func() {
		dialer.DefaultSocketHook = orig
		dialer.DefaultAddressTransform = origTransform
	})

	dialer.DefaultSocketHook = func(_, _ string, _ syscall.RawConn) error { return nil }
	installSocketHook(&hookPlatform{enabled: false})
	if dialer.DefaultSocketHook != nil {
		t.Fatal("opt-out must clear DefaultSocketHook")
	}
	if dialer.DefaultAddressTransform != nil {
		t.Fatal("opt-out must clear DefaultAddressTransform")
	}

	platform := &hookPlatform{enabled: true}
	installSocketHook(platform)
	if dialer.DefaultSocketHook == nil {
		t.Fatal("opt-in must install DefaultSocketHook")
	}
	if dialer.DefaultAddressTransform == nil {
		t.Fatal("opt-in must install DefaultAddressTransform")
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	raw, err := pc.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatalf("syscallconn: %v", err)
	}
	if err := dialer.DefaultSocketHook("udp", "1.1.1.1:53", raw); err != nil {
		t.Fatalf("hook returned error: %v", err)
	}
	if platform.callCount != 1 {
		t.Fatalf("AutoDetectControl called %d times, want 1", platform.callCount)
	}
	if platform.gotFd <= 0 {
		t.Fatalf("AutoDetectControl got fd %d, want a valid descriptor", platform.gotFd)
	}
}

func TestSocketHookLeavesLoopbackUnscoped(t *testing.T) {
	orig := dialer.DefaultSocketHook
	origTransform := dialer.DefaultAddressTransform
	t.Cleanup(func() {
		dialer.DefaultSocketHook = orig
		dialer.DefaultAddressTransform = origTransform
	})

	platform := &hookPlatform{enabled: true}
	installSocketHook(platform)
	if dialer.DefaultSocketHook == nil {
		t.Fatal("opt-in must install DefaultSocketHook")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener available: %v", err)
	}
	defer listener.Close()

	rawConnOf := func(t *testing.T) syscall.RawConn {
		t.Helper()
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { conn.Close() })
		raw, err := conn.(*net.TCPConn).SyscallConn()
		if err != nil {
			t.Fatalf("syscall conn: %v", err)
		}
		return raw
	}

	for _, address := range []string{
		"127.0.0.1:1053", "[::1]:53", "localhost:53", listener.Addr().String(),
		"169.254.1.1:53",
		"[fe80::1]:53",
		"224.0.0.251:5353",
		"0.0.0.0:0",
	} {
		before := platform.callCount
		if err := dialer.DefaultSocketHook("udp", address, rawConnOf(t)); err != nil {
			t.Fatalf("hook returned an error for %q: %v", address, err)
		}
		if platform.callCount != before {
			t.Fatalf("%q was scoped to an interface; upstream leaves a non-global-unicast destination unbound", address)
		}
	}

	for _, address := range []string{"223.5.5.5:53", "[2400:3200::1]:53", "example.com:443"} {
		before := platform.callCount
		if err := dialer.DefaultSocketHook("udp", address, rawConnOf(t)); err != nil {
			t.Fatalf("hook returned an error for %q: %v", address, err)
		}
		if platform.callCount != before+1 {
			t.Fatalf("%q must still be scoped: callCount %d -> %d", address, before, platform.callCount)
		}
	}

	before := platform.callCount
	if err := dialer.DefaultSocketHook("udp", "", rawConnOf(t)); err != nil {
		t.Fatalf("hook returned an error for an empty address: %v", err)
	}
	if platform.callCount != before+1 {
		t.Fatalf("an address the hook cannot read must stay scoped: callCount %d -> %d", before, platform.callCount)
	}
}
