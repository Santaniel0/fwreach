// Package netpkt holds the packet and host model shared by the rule
// frontends and the simulator.
package netpkt

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Family is the IP version of a packet.
type Family uint8

const (
	IPv4 Family = iota + 1
	IPv6
)

func (f Family) String() string {
	switch f {
	case IPv4:
		return "ipv4"
	case IPv6:
		return "ipv6"
	}
	return "family(" + strconv.Itoa(int(f)) + ")"
}

// FamilyOf reports the family of addr, treating v4-mapped v6 as IPv4.
func FamilyOf(addr netip.Addr) Family {
	if addr.Unmap().Is4() {
		return IPv4
	}
	return IPv6
}

// Proto is an IP protocol number.
type Proto uint8

const (
	ProtoICMP   Proto = 1
	ProtoTCP    Proto = 6
	ProtoUDP    Proto = 17
	ProtoICMPv6 Proto = 58
)

func (p Proto) String() string {
	switch p {
	case ProtoICMP:
		return "icmp"
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMPv6:
		return "icmpv6"
	}
	return strconv.Itoa(int(p))
}

// ParseProto accepts protocol names used by iptables, nft and ss, or a number.
func ParseProto(s string) (Proto, error) {
	switch strings.ToLower(s) {
	case "tcp":
		return ProtoTCP, nil
	case "udp":
		return ProtoUDP, nil
	case "icmp":
		return ProtoICMP, nil
	case "icmpv6", "ipv6-icmp", "icmp6":
		return ProtoICMPv6, nil
	}
	n, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("unknown protocol %q", s)
	}
	return Proto(n), nil
}

// Hook is a netfilter hook point.
type Hook uint8

const (
	Prerouting Hook = iota + 1
	Input
	Forward
	Output
	Postrouting
)

func (h Hook) String() string {
	switch h {
	case Prerouting:
		return "prerouting"
	case Input:
		return "input"
	case Forward:
		return "forward"
	case Output:
		return "output"
	case Postrouting:
		return "postrouting"
	}
	return "hook(" + strconv.Itoa(int(h)) + ")"
}

// ParseHook parses an nft hook name.
func ParseHook(s string) (Hook, bool) {
	for h := Prerouting; h <= Postrouting; h++ {
		if h.String() == s {
			return h, true
		}
	}
	return 0, false
}

// Tristate is the result of evaluating a match: rules can contain matches
// fwreach does not model, and those must stay visible as Unknown.
type Tristate uint8

const (
	No Tristate = iota
	Yes
	Unknown
)

func (t Tristate) String() string {
	switch t {
	case No:
		return "no"
	case Yes:
		return "yes"
	}
	return "unknown"
}

// Bool converts a definite answer.
func Bool(b bool) Tristate {
	if b {
		return Yes
	}
	return No
}

// Not negates; Unknown stays Unknown.
func (t Tristate) Not() Tristate {
	switch t {
	case Yes:
		return No
	case No:
		return Yes
	}
	return Unknown
}

// Packet is the first packet of an inbound connection (conntrack state NEW)
// as it moves through the hooks. DNAT rewrites Dst and DstPort; the Orig
// fields keep what the sender addressed, like conntrack's original tuple.
type Packet struct {
	Family      Family
	Proto       Proto
	Src         netip.Addr
	Dst         netip.Addr
	SrcPort     uint16
	DstPort     uint16
	InIface     string
	OutIface    string
	Mark        uint32
	OrigDst     netip.Addr
	OrigDstPort uint16
	DNATed      bool
}

// NewInbound builds a NEW packet arriving on iface.
func NewInbound(proto Proto, src, dst netip.Addr, dport uint16, iface string) Packet {
	return Packet{
		Family:      FamilyOf(dst),
		Proto:       proto,
		Src:         src,
		Dst:         dst,
		SrcPort:     40000,
		DstPort:     dport,
		InIface:     iface,
		OrigDst:     dst,
		OrigDstPort: dport,
	}
}

// AddrType mirrors the address classes of iptables addrtype and nft fib type.
type AddrType uint8

const (
	AddrUnicast AddrType = 1 << iota
	AddrLocal
	AddrBroadcast
	AddrMulticast
)

// Iface is a host network interface with its addresses.
type Iface struct {
	Name     string
	Loopback bool
	Addrs    []netip.Prefix
}

// Host is the part of the host's network state the simulator needs:
// which addresses are local and which subnets are directly connected.
type Host struct {
	Ifaces []Iface
}

// IsLocal reports whether addr belongs to the host.
func (h *Host) IsLocal(addr netip.Addr) bool {
	if addr.IsLoopback() {
		return true
	}
	for _, ifc := range h.Ifaces {
		for _, p := range ifc.Addrs {
			if p.Addr() == addr {
				return true
			}
		}
	}
	return false
}

// TypeOf classifies addr the way the kernel's fib lookup does for the
// cases rulesets use in practice.
func (h *Host) TypeOf(addr netip.Addr) AddrType {
	if h.IsLocal(addr) {
		return AddrLocal
	}
	if addr.IsMulticast() {
		return AddrMulticast
	}
	if addr.Is4() {
		if addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			return AddrBroadcast
		}
		for _, ifc := range h.Ifaces {
			for _, p := range ifc.Addrs {
				if p.Addr().Is4() && p.Bits() < 31 && LastAddr(p.Masked()) == addr {
					return AddrBroadcast
				}
			}
		}
	}
	return AddrUnicast
}

// Route returns the interface whose connected subnet contains addr,
// preferring the longest prefix. Loopback is never a route target here.
func (h *Host) Route(addr netip.Addr) (string, bool) {
	best, bestBits := "", -1
	for _, ifc := range h.Ifaces {
		if ifc.Loopback {
			continue
		}
		for _, p := range ifc.Addrs {
			if p.Masked().Contains(addr) && p.Bits() > bestBits {
				best, bestBits = ifc.Name, p.Bits()
			}
		}
	}
	return best, bestBits >= 0
}

// LastAddr returns the highest address inside p.
func LastAddr(p netip.Prefix) netip.Addr {
	p = p.Masked()
	if p.Addr().Is4() {
		b := p.Addr().As4()
		setHostBits(b[:], p.Bits())
		return netip.AddrFrom4(b)
	}
	b := p.Addr().As16()
	setHostBits(b[:], p.Bits())
	return netip.AddrFrom16(b)
}

func setHostBits(b []byte, bits int) {
	for i := range b {
		switch {
		case bits >= 8:
			bits -= 8
		case bits > 0:
			b[i] |= 0xff >> bits
			bits = 0
		default:
			b[i] = 0xff
		}
	}
}
