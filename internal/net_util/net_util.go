package net_util

import (
	"net"
	"net/netip"

	"github.com/free5gc/ausf/internal/logger"
)

func RegisterAddr(registerIP string) netip.Addr {
	ips, err := net.LookupIP(registerIP)
	if err != nil {
		logger.InitLog.Errorf("Resolve RegisterIP hostname %s failed: %+v", registerIP, err)
	}
	ip, err := netip.ParseAddr(ips[0].String())
	if err != nil {
		logger.InitLog.Errorf("Parse RegisterIP hostname %s failed: %+v", registerIP, err)
	}
	return ip
}
