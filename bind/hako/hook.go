package hako

import (
	"net"
	"net/netip"
	"syscall"

	"github.com/TokenPLS/Hako/common/atomic"
	"github.com/TokenPLS/Hako/component/dialer"
	"github.com/TokenPLS/Hako/log"
)

func interfaceScopableTarget(address string) bool {
	if address == "" {
		return true
	}
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			host = address
		}
		if host == "localhost" {
			return false
		}
		addr, parseErr := netip.ParseAddr(host)
		if parseErr != nil {
			return true
		}
		return addr.Unmap().IsGlobalUnicast()
	}
	return addrPort.Addr().Unmap().IsGlobalUnicast()
}

var publishedInterfaceIndex = atomic.NewInt32(0)

var publishedPathCellular atomic.Bool

var noPathDialsLogged atomic.Bool

var suspendedDialsLogged atomic.Bool

func installSocketHook(platform PlatformInterface) {
	if platform == nil || !platform.UsePlatformAutoDetectInterfaceControl() {
		dialer.DefaultSocketHook = nil
		dialer.SocketHookScopesInterfaceOnly = false
		installPhysicalAddressTransform(false)
		return
	}
	installPhysicalAddressTransform(true)
	dialer.SocketHookScopesInterfaceOnly = true
	dialer.DefaultSocketHook = func(_, address string, conn syscall.RawConn) error {
		if !interfaceScopableTarget(address) {
			return nil
		}
		if publishedInterfaceIndex.Load() == 0 {
			if noPathDialsLogged.CompareAndSwap(false, true) {
				log.Warnln("[Apple] no physical path is published; outbound sockets dial unbound until one is, rather than failing")
			}
			return nil
		}
		noPathDialsLogged.Store(false)
		if index := publishedInterfaceIndex.Load(); bindingSuspended(index) {
			if suspendedDialsLogged.CompareAndSwap(false, true) {
				log.Warnln("[Apple] outbound sockets dial unbound: the bearer witness found interface index %d bound but not carrying; binding resumes at the next path change", index)
			}
			return nil
		}
		suspendedDialsLogged.Store(false)
		var ctrlErr error
		if err := conn.Control(func(fd uintptr) {
			ctrlErr = platform.AutoDetectInterfaceControl(int32(fd))
		}); err != nil {
			return err
		}
		return ctrlErr
	}
}
