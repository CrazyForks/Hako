package hako

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/TokenPLS/Hako/config"
	"github.com/TokenPLS/Hako/hub/route"
	"github.com/TokenPLS/Hako/log"
)

const clashAPISocketName = "clash.sock"

const clashAPIMaxUnixPathBytes = 103

var (
	clashAPIStartTimeout = 3 * time.Second
	clashAPIStopTimeout  = time.Second
	clashAPIPollInterval = 20 * time.Millisecond
)

func ClashAPIPath() string {
	setupMu.Lock()
	defer setupMu.Unlock()
	return bridgeSafeString(setupClashAPIPath)
}

func bindingSocketPathFor(path string) string {
	if !currentRuntimePolicy(true).bindsUnixControlSocket {
		return ""
	}
	return path
}

func startControlPlane(cfg *config.Config, path string) error {
	if path == "" {
		return fmt.Errorf("hako: Clash API path is empty; call Setup before Start")
	}
	socket := bindingSocketPathFor(path)
	if socket != "" {
		if len([]byte(socket)) > clashAPIMaxUnixPathBytes {
			return fmt.Errorf("hako: Clash API Unix path is %d bytes; Darwin limit is %d: %s", len([]byte(socket)), clashAPIMaxUnixPathBytes, socket)
		}
		_ = os.Remove(socket)
	}
	route.SetEmbedMode(true)
	route.SetGeoUpdaterAllowed(!currentRuntimeProfile().inheritsIOSPacketTunnelBehavior())
	server := recreateControlPlane(cfg, socket)
	if server.Addr != "" || server.TLSAddr != "" {
		log.Infoln("[Apple] external-controller listening as configured: addr=%q tls=%q", server.Addr, server.TLSAddr)
	}
	if socket == "" {
		return nil
	}

	if err := secureBindingControlSocket(socket); err != nil {
		stopClashAPI(socket)
		return err
	}

	deadline := time.Now().Add(clashAPIStartTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", socket, clashAPIPollInterval)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(clashAPIPollInterval)
	}
	stopClashAPI(socket)
	return fmt.Errorf("hako: Clash API Unix listener not ready: %w", lastErr)
}

func secureBindingControlSocket(socket string) error {
	if err := os.Chmod(socket, 0o600); err != nil {
		return fmt.Errorf("hako: secure Clash API Unix socket: %w", err)
	}
	return nil
}

func stopClashAPI(path string) {
	route.ReCreateServer(&route.Config{})
	userControllerLive.Store(false)
	if path == "" {
		return
	}
	socket := bindingSocketPathFor(path)
	if socket == "" {
		return
	}
	deadline := time.Now().Add(clashAPIStopTimeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", socket, clashAPIPollInterval)
		if err != nil {
			break
		}
		_ = conn.Close()
		time.Sleep(clashAPIPollInterval)
	}
	_ = os.Remove(socket)
}
