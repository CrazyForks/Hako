package hako

import (
	"net"
	"net/netip"
	"syscall"

	"github.com/TokenPLS/Hako/component/dialer"
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
		var ctrlErr error
		if err := conn.Control(func(fd uintptr) {
			ctrlErr = platform.AutoDetectInterfaceControl(int32(fd))
		}); err != nil {
			return err
		}
		return ctrlErr
	}
}
