package net

import (
	"net/netip"
	"testing"
)

func TestRegisterAddrWithLocalhost(t *testing.T) {
	expected_addr, err := netip.ParseAddr("::1")
	if err != nil {
		t.Errorf("invalid expected IP: %+v", expected_addr)
	}

	addr := RegisterAddr("localhost")
	if addr != expected_addr {
		t.Errorf("invalid IP: %+v", addr)
	}
}

func TestRegisterAddrWithIpV4(t *testing.T) {
	expected_addr, err := netip.ParseAddr("127.0.0.1")
	if err != nil {
		t.Errorf("invalid expected IP: %+v", expected_addr)
	}

	addr := RegisterAddr("127.0.0.1")
	if addr != expected_addr {
		t.Errorf("invalid IP: %+v", addr)
	}
}

func TestRegisterAddrWithIpV6(t *testing.T) {
	expected_addr, err := netip.ParseAddr("2001:db8::1:0:0:1")
	if err != nil {
		t.Errorf("invalid expected IP: %+v", expected_addr)
	}

	addr := RegisterAddr("2001:db8::1:0:0:1")
	if addr != expected_addr {
		t.Errorf("invalid IP: %+v", addr)
	}
}
