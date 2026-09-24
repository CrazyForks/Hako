//go:build darwin

package hako

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"

	"github.com/TokenPLS/Hako/adapter/inbound"
	"github.com/TokenPLS/Hako/log"

	"golang.org/x/sys/unix"
)

func installListenerScopeHooks(underNetworkExtension bool) {
	if !underNetworkExtension {
		inbound.DefaultListenerHook = nil
		inbound.DefaultListenerWrapper = nil
		return
	}
	inbound.DefaultListenerHook = listenerScopeControl
	inbound.DefaultListenerWrapper = listenerLoopbackCompanion
	log.Infoln("[Apple] inbound listeners run under the Network Extension socket scope; loopback faces will be explicitly bound to the loopback interface")
}

func loopbackInterfaceIndex() (int, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return 0, fmt.Errorf("enumerate interfaces: %w", err)
	}
	for _, candidate := range interfaces {
		if candidate.Flags&net.FlagLoopback != 0 && candidate.Flags&net.FlagUp != 0 {
			return candidate.Index, nil
		}
	}
	return 0, errors.New("no up loopback interface")
}

func listenerScopeControl(network, address string, conn syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsLoopback() {
		return nil
	}
	index, err := loopbackInterfaceIndex()
	if err != nil {
		return fmt.Errorf("bind %s listener to loopback interface: %w", address, err)
	}
	var opErr error
	controlErr := conn.Control(func(fd uintptr) {
		if addr.Unmap().Is6() {
			opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, index)
		} else {
			opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, index)
		}
	})
	if controlErr != nil {
		return controlErr
	}
	if opErr != nil {
		return fmt.Errorf("bind %s listener to loopback interface index %d: %w", address, index, opErr)
	}
	return nil
}

func listenerLoopbackCompanion(network, address string, primary net.Listener, relisten func(context.Context, string, string) (net.Listener, error)) (net.Listener, error) {
	if !strings.HasPrefix(network, "tcp") {
		return primary, nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return primary, nil
	}
	if host != "" {
		addr, parseErr := netip.ParseAddr(host)
		if parseErr != nil || !addr.IsUnspecified() {
			return primary, nil
		}
	}
	tcpAddr, ok := primary.Addr().(*net.TCPAddr)
	if !ok {
		return primary, nil
	}
	port := fmt.Sprintf("%d", tcpAddr.Port)

	wantV4 := network != "tcp6" && host != "::"
	wantV6 := network != "tcp4" && host != "0.0.0.0"
	if host == "::" && network == "tcp" {
		wantV4 = true
	}

	companions := make([]net.Listener, 0, 2)
	fail := func(err error) (net.Listener, error) {
		for _, companion := range companions {
			_ = companion.Close()
		}
		_ = primary.Close()
		return nil, err
	}
	if wantV4 {
		companion, listenErr := relisten(context.Background(), "tcp4", net.JoinHostPort("127.0.0.1", port))
		if listenErr != nil {
			return fail(fmt.Errorf("hako: loopback companion for %s listener on port %s: %w", network, port, listenErr))
		}
		companions = append(companions, companion)
	}
	if wantV6 {
		companion, listenErr := relisten(context.Background(), "tcp6", net.JoinHostPort("::1", port))
		if listenErr != nil {
			return fail(fmt.Errorf("hako: loopback companion for %s listener on port %s: %w", network, port, listenErr))
		}
		companions = append(companions, companion)
	}
	if len(companions) == 0 {
		return primary, nil
	}
	return newCompanionListener(primary, companions), nil
}

type companionAccept struct {
	conn net.Conn
	err  error
}

type companionListener struct {
	primary   net.Listener
	listeners []net.Listener
	results   chan companionAccept
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func newCompanionListener(primary net.Listener, companions []net.Listener) *companionListener {
	merged := &companionListener{
		primary:   primary,
		listeners: append([]net.Listener{primary}, companions...),
		results:   make(chan companionAccept),
		closed:    make(chan struct{}),
	}
	for _, listener := range merged.listeners {
		go merged.pump(listener)
	}
	return merged
}

func (l *companionListener) pump(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case l.results <- companionAccept{err: err}:
			case <-l.closed:
				return
			}
			continue
		}
		select {
		case l.results <- companionAccept{conn: conn}:
		case <-l.closed:
			conn.Close()
			return
		}
	}
}

func (l *companionListener) Accept() (net.Conn, error) {
	select {
	case result := <-l.results:
		return result.conn, result.err
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *companionListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
		for _, listener := range l.listeners {
			if err := listener.Close(); err != nil && l.closeErr == nil {
				l.closeErr = err
			}
		}
	})
	return l.closeErr
}

func (l *companionListener) Addr() net.Addr {
	return l.primary.Addr()
}
