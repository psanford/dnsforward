package main

import (
	"net"

	"github.com/coreos/go-systemd/v22/activation"
)

func activationConns() ([]net.Listener, []net.PacketConn) {
	files := activation.Files(true)
	listeners := make([]net.Listener, 0)
	packetConns := make([]net.PacketConn, 0)

	for _, f := range files {
		if l, err := net.FileListener(f); err == nil {
			listeners = append(listeners, l)
			f.Close()
		} else if pc, err := net.FilePacketConn(f); err == nil {
			packetConns = append(packetConns, pc)
			f.Close()
		}
	}

	return listeners, packetConns
}
