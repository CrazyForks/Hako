package tun

import (
	"context"
	"net/netip"
	"time"

	"github.com/metacubex/mipstack"
	"github.com/metacubex/sing-tun/internal/gtcpip/header"
	"github.com/metacubex/sing/common"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"
)

type Mipstack struct {
	ctx                  context.Context
	tun                  Tun
	mtu                  uint32
	recvMsgX             bool
	inet4Address         netip.Addr
	inet6Address         netip.Addr
	inet4LoopbackAddress []netip.Addr
	inet6LoopbackAddress []netip.Addr
	broadcastAddr        netip.Addr
	icmpMapping          *DirectRouteMapping
	handler              Handler
	logger               logger.Logger
	stack                *mipstack.Stack
	icmpSlots            chan struct{}
	deferred *deferredFlowGroup
}

func NewMipstack(options StackOptions) (Stack, error) {
	var (
		inet4Address netip.Addr
		inet6Address netip.Addr
	)
	if len(options.TunOptions.Inet4Address) > 0 {
		inet4Address = options.TunOptions.Inet4Address[0].Addr()
	}
	if len(options.TunOptions.Inet6Address) > 0 {
		inet6Address = options.TunOptions.Inet6Address[0].Addr()
	}

	s := &Mipstack{
		ctx:                  options.Context,
		tun:                  options.Tun,
		mtu:                  options.TunOptions.MTU,
		recvMsgX:             options.TunOptions.EXP_RecvMsgX,
		inet4Address:         inet4Address,
		inet6Address:         inet6Address,
		inet4LoopbackAddress: options.TunOptions.Inet4LoopbackAddress,
		inet6LoopbackAddress: options.TunOptions.Inet6LoopbackAddress,
		broadcastAddr:        BroadcastAddr(options.TunOptions.Inet4Address),
		icmpMapping:          NewDirectRouteMapping(options.ICMPTimeout),
		icmpSlots:            make(chan struct{}, 16),
		deferred:             newDeferredFlowGroup(),
		handler:              options.Handler,
		logger:               options.Logger,
	}
	return s, nil
}

func (s *Mipstack) config() mipstack.Config {
	var routes []mipstack.Route
	if s.mtu != 0 && s.mtu < 1280 && !s.inet6Address.IsValid() {
		routes = []mipstack.Route{{Destination: netip.MustParsePrefix("0.0.0.0/0")}}
	}
	config := mipstack.Config{
		Routes:      routes,
		Promiscuous: true,
		MTU:         s.mtu,
		TCP: mipstack.TCPSocketDefaults{
			KeepAlive: true,
			KeepAliveConfig: mipstack.KeepAliveConfig{
				Idle:     15 * time.Second,
				Interval: 15 * time.Second,
			},
		},
	}
	if common.LowMemory {
		config.TCP.ReceiveBuffer = 32 * 1024
		config.TCP.MaximumReceiveBuffer = 128 * 1024
		config.TCP.SendBuffer = 32 * 1024
		config.TCP.MaximumSendBuffer = 128 * 1024
	}
	return config
}

func (s *Mipstack) Start() error {
	stack, err := mipstack.New(s.config())
	if err != nil {
		return err
	}
	defer func() {
		if s.stack == nil {
			_ = stack.Close()
		}
	}()
	_, err = mipstack.NewTCPForwarder(stack, mipstack.TCPForwarderOptions{}, s.forwardTCP)
	if err != nil {
		return err
	}
	_, err = mipstack.NewUDPForwarder(stack, mipstack.UDPForwarderOptions{}, s.forwardUDP)
	if err != nil {
		return err
	}
	_, err = mipstack.NewICMPForwarder(stack, mipstack.ICMPForwarderOptions{}, s.forwardICMP)
	if err != nil {
		return err
	}
	_, err = mipstack.NewIPForwarder(stack, mipstack.IPForwarderOptions{}, func(request *mipstack.IPForwarderRequest) {
		_ = request.Reject()
	})
	if err != nil {
		return err
	}
	err = stack.Start()
	if err != nil {
		return err
	}
	s.stack = stack
	go s.readLoop()
	go s.writeLoop()
	return nil
}

func (s *Mipstack) Close() error {
	if s.stack == nil {
		return nil
	}
	s.deferred.shutdown()
	return s.stack.Close()
}

func (s *Mipstack) readLoop() {
	device := s.tun
	if linuxTUN, isLinuxTUN := device.(LinuxTUN); isLinuxTUN && linuxTUN.FrontHeadroom() > 0 {
		s.batchLoopLinux(linuxTUN, linuxTUN.BatchSize())
		return
	}
	if winTun, isWinTun := device.(WinTun); isWinTun {
		s.wintunLoop(winTun)
		return
	}
	offset := 0
	if darwinTUN, isDarwinTUN := device.(DarwinTUN); isDarwinTUN {
		if s.recvMsgX {
			s.batchLoopDarwin(darwinTUN)
			return
		}
		offset = 4
	}
	buffer := make([]byte, int(s.mtu)+offset)
	for {
		n, err := device.Read(buffer)
		if n > offset {
			s.processPacket(buffer[offset:n])
		}
		if err != nil {
			if E.IsClosed(err) {
				return
			}
			s.logger.Error(E.Cause(err, "read packet"))
		}
	}
}

func (s *Mipstack) wintunLoop(winTun WinTun) {
	for {
		packet, release, err := winTun.ReadPacket()
		if len(packet) > 0 {
			s.processPacket(packet)
		}
		if release != nil {
			release()
		}
		if err != nil {
			if !E.IsClosed(err) {
				s.logger.Error(E.Cause(err, "read packet"))
			}
			return
		}
	}
}

func (s *Mipstack) batchLoopLinux(linuxTUN LinuxTUN, batchSize int) {
	offset := linuxTUN.FrontHeadroom()
	buffers := make([][]byte, batchSize)
	for i := range buffers {
		buffers[i] = make([]byte, int(s.mtu)+offset)
	}
	sizes := make([]int, len(buffers))
	for {
		n, err := linuxTUN.BatchRead(buffers, offset, sizes)
		for i := 0; i < n; i++ {
			s.processPacket(buffers[i][offset : offset+sizes[i]])
		}
		if err != nil {
			if E.IsClosed(err) {
				return
			}
			s.logger.Error(E.Cause(err, "batch read packet"))
		}
	}
}

func (s *Mipstack) batchLoopDarwin(darwinTUN DarwinTUN) {
	for {
		buffers, err := darwinTUN.BatchRead()
		for _, buffer := range buffers {
			s.processPacket(buffer.Bytes())
			buffer.Release()
		}
		if err != nil {
			if E.IsClosed(err) {
				return
			}
			s.logger.Error(E.Cause(err, "batch read packet"))
		}
	}
}

func (s *Mipstack) processPacket(packet []byte) {
	destination, ok := mipsPacketDestination(packet)
	if !ok {
		return
	}
	if destination == s.broadcastAddr || !destination.IsGlobalUnicast() {
		if err := s.writePacket(packet); err != nil {
			s.logger.Trace(E.Cause(err, "write packet"))
		}
		return
	}
	addresses := s.inet4LoopbackAddress
	if destination.Is6() {
		addresses = s.inet6LoopbackAddress
	}
	for _, address := range addresses {
		if address != destination {
			continue
		}
		parsed, err := mipstack.ParseIPPacket(packet)
		if err != nil {
			return
		}
		if !mipsValidLoopbackPacket(parsed) {
			break
		}
		response := append([]byte(nil), packet...)
		if destination.Is4() {
			ip := header.IPv4(response)
			ip.SetSourceAddr(destination)
			ip.SetDestinationAddr(parsed.Source)
		} else {
			ip := header.IPv6(response)
			ip.SetSourceAddr(destination)
			ip.SetDestinationAddr(parsed.Source)
		}
		if err := s.writePacket(response); err != nil {
			s.logger.Trace(E.Cause(err, "write packet"))
		}
		return
	}
	_, _ = s.stack.Write([][]byte{packet}, 0)
}

func mipsPacketDestination(packet []byte) (netip.Addr, bool) {
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		ip := header.IPv4(packet)
		if ip.IsValid(len(packet)) {
			return ip.DestinationAddr(), true
		}
	case header.IPv6Version:
		ip := header.IPv6(packet)
		if ip.IsValid(len(packet)) {
			return ip.DestinationAddr(), true
		}
	}
	return netip.Addr{}, false
}

func mipsValidLoopbackPacket(parsed mipstack.IPPacket) bool {
	if fragment, ok := parsed.Fragment(); ok && !fragment.IsAtomic() {
		if fragment.Offset != 0 {
			return fragment.Protocol == mipstack.ProtocolTCP
		}
		parsed.Protocol, parsed.Payload = fragment.Protocol, fragment.Payload
		parsed.MoreFragments, parsed.FragmentOffset = false, 0
		protocol, _, err := parsed.UpperLayer()
		return err == nil && protocol == mipstack.ProtocolTCP
	}
	_, err := parsed.TCPSegment()
	return err == nil
}

func (s *Mipstack) writeLoop() {
	buffers := make([][]byte, s.stack.BatchSize())
	for i := range buffers {
		buffers[i] = make([]byte, int(s.mtu))
	}
	sizes := make([]int, len(buffers))
	packets := make([][]byte, len(buffers))
	var writeBuffers [][]byte
	for {
		n, err := s.stack.Read(buffers, sizes, 0)
		for i := 0; i < n; i++ {
			packets[i] = buffers[i][:sizes[i]]
		}
		if writeErr := s.writePacketsWithBuffers(packets[:n], &writeBuffers); writeErr != nil {
			if E.IsClosed(writeErr) {
				return
			}
			s.logger.Trace(E.Cause(writeErr, "write packet"))
		}
		if err != nil {
			if !E.IsClosed(err) {
				s.logger.Error(E.Cause(err, "read stack packet"))
			}
			return
		}
	}
}

func (s *Mipstack) writePacket(packet []byte) error {
	return s.writePackets([][]byte{packet})
}

func (s *Mipstack) writePackets(packets [][]byte) error {
	var writeBuffers [][]byte
	return s.writePacketsWithBuffers(packets, &writeBuffers)
}

func (s *Mipstack) writePacketsWithBuffers(packets [][]byte, scratch *[][]byte) error {
	if len(packets) == 0 {
		return nil
	}
	if linux, ok := s.tun.(LinuxTUN); ok && linux.FrontHeadroom() > 0 {
		offset := linux.FrontHeadroom()
		for len(*scratch) < len(packets) {
			*scratch = append(*scratch, make([]byte, offset+65535))
		}
		writeBuffers := (*scratch)[:len(packets)]
		for i, packet := range packets {
			writeBuffers[i] = writeBuffers[i][:offset+len(packet)]
			copy(writeBuffers[i][offset:], packet)
		}
		_, err := linux.BatchWrite(writeBuffers, offset)
		return err
	}
	if darwin, ok := s.tun.(DarwinTUN); ok {
		if len(*scratch) == 0 {
			*scratch = append(*scratch, nil)
		}
		for _, packet := range packets {
			if cap((*scratch)[0]) < 4+len(packet) {
				(*scratch)[0] = make([]byte, 4+len(packet))
			}
			buffer := (*scratch)[0][:4+len(packet)]
			copy(buffer, []byte{0, 0, 0, 2})
			if header.IPVersion(packet) == header.IPv6Version {
				buffer[3] = 30
			}
			copy(buffer[4:], packet)
			if _, err := darwin.Write(buffer); err != nil {
				return err
			}
		}
		return nil
	}
	for _, packet := range packets {
		_, err := s.tun.Write(packet)
		if err != nil {
			return err
		}
	}
	return nil
}
