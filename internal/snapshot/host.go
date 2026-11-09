package snapshot

import (
	"bufio"
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/Santaniel0/fwreach/internal/netpkt"
)

// Listener is a listening socket from ss.
type Listener struct {
	Proto    netpkt.Proto
	Addr     netip.Addr // invalid for "*"
	Port     uint16
	Iface    string // set when the socket is bound to a device ("%lo")
	Process  string
	Wildcard bool
}

// Accepts reports whether a packet to dst arriving on iface would reach
// this socket. A "[::]" socket is assumed dual-stack, which is the Linux
// default (net.ipv6.bindv6only=0).
func (l Listener) Accepts(dst netip.Addr, iface string) bool {
	if l.Iface != "" && l.Iface != iface {
		return false
	}
	switch {
	case l.Wildcard:
		return true
	case l.Addr == netip.IPv4Unspecified():
		return dst.Is4()
	case l.Addr == netip.IPv6Unspecified():
		return true
	}
	return l.Addr == dst.Unmap()
}

// Bound renders the address the socket is bound to.
func (l Listener) Bound() string {
	s := "*"
	if !l.Wildcard {
		s = l.Addr.String()
	}
	if l.Iface != "" {
		s += "%" + l.Iface
	}
	return s
}

// ParseSS reads `ss -Hlntup` output.
func ParseSS(r io.Reader) ([]Listener, error) {
	var out []Listener
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		if len(f) < 5 {
			return nil, fmt.Errorf("ss line %d: too few fields: %q", n, sc.Text())
		}
		proto, err := netpkt.ParseProto(f[0])
		if err != nil {
			return nil, fmt.Errorf("ss line %d: %w", n, err)
		}
		l, err := parseLocal(f[4])
		if err != nil {
			return nil, fmt.Errorf("ss line %d: %w", n, err)
		}
		l.Proto = proto
		if len(f) > 6 {
			l.Process = processName(strings.Join(f[6:], " "))
		}
		out = append(out, l)
	}
	return out, sc.Err()
}

func parseLocal(s string) (Listener, error) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return Listener{}, fmt.Errorf("local address %q has no port", s)
	}
	port, err := strconv.ParseUint(s[i+1:], 10, 16)
	if err != nil {
		return Listener{}, fmt.Errorf("local address %q: bad port", s)
	}
	l := Listener{Port: uint16(port)}
	host := strings.TrimSuffix(strings.TrimPrefix(s[:i], "["), "]")
	host, l.Iface, _ = strings.Cut(host, "%")
	if host == "*" {
		l.Wildcard = true
		return l, nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return Listener{}, fmt.Errorf("local address %q: %w", s, err)
	}
	l.Addr = addr.Unmap()
	return l, nil
}

func processName(s string) string {
	_, rest, ok := strings.Cut(s, `(("`)
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(rest, `"`)
	return name
}

type ipAddrJSON struct {
	IfName   string `json:"ifname"`
	LinkType string `json:"link_type"`
	AddrInfo []struct {
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
		Scope     string `json:"scope"`
	} `json:"addr_info"`
}

// ParseIPAddr reads `ip -j addr` output. Link-local addresses are kept for
// locality checks but never used as probe destinations.
func ParseIPAddr(r io.Reader) ([]netpkt.Iface, error) {
	var raw []ipAddrJSON
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode ip -j addr: %w", err)
	}
	var out []netpkt.Iface
	for _, ifc := range raw {
		it := netpkt.Iface{Name: ifc.IfName, Loopback: ifc.LinkType == "loopback"}
		for _, a := range ifc.AddrInfo {
			addr, err := netip.ParseAddr(a.Local)
			if err != nil {
				return nil, fmt.Errorf("interface %s: %w", ifc.IfName, err)
			}
			p, err := addr.Prefix(a.PrefixLen)
			if err != nil {
				return nil, fmt.Errorf("interface %s: %w", ifc.IfName, err)
			}
			it.Addrs = append(it.Addrs, netip.PrefixFrom(addr, p.Bits()))
		}
		out = append(out, it)
	}
	return out, nil
}

// Published is one port mapping of a container.
type Published struct {
	Proto         netpkt.Proto
	HostIP        netip.Addr // invalid means all addresses
	HostPort      uint16
	ContainerPort uint16
}

// Container is the part of `docker inspect` fwreach uses.
type Container struct {
	Name  string
	IPs   []netip.Addr
	Ports []Published
}

type inspectJSON struct {
	Name            string `json:"Name"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
		Networks map[string]struct {
			IPAddress         string `json:"IPAddress"`
			GlobalIPv6Address string `json:"GlobalIPv6Address"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

// ParseDockerInspect reads `docker inspect` output for running containers.
func ParseDockerInspect(r io.Reader) ([]Container, error) {
	var raw []inspectJSON
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode docker inspect: %w", err)
	}
	var out []Container
	for _, c := range raw {
		ct := Container{Name: strings.TrimPrefix(c.Name, "/")}
		for _, n := range c.NetworkSettings.Networks {
			for _, s := range []string{n.IPAddress, n.GlobalIPv6Address} {
				if a, err := netip.ParseAddr(s); err == nil {
					ct.IPs = append(ct.IPs, a)
				}
			}
		}
		for key, binds := range c.NetworkSettings.Ports {
			port, proto, _ := strings.Cut(key, "/")
			cp, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("container %s: port %q", ct.Name, key)
			}
			pr, err := netpkt.ParseProto(proto)
			if err != nil {
				return nil, fmt.Errorf("container %s: %w", ct.Name, err)
			}
			for _, b := range binds {
				hp, err := strconv.ParseUint(b.HostPort, 10, 16)
				if err != nil {
					return nil, fmt.Errorf("container %s: host port %q", ct.Name, b.HostPort)
				}
				pub := Published{Proto: pr, HostPort: uint16(hp), ContainerPort: uint16(cp)}
				if a, err := netip.ParseAddr(b.HostIP); err == nil && !a.IsUnspecified() {
					pub.HostIP = a
				}
				ct.Ports = append(ct.Ports, pub)
			}
		}
		// Docker returns these as maps; sort for stable output.
		slices.SortFunc(ct.IPs, netip.Addr.Compare)
		slices.SortFunc(ct.Ports, func(a, b Published) int {
			return cmp.Or(cmp.Compare(a.HostPort, b.HostPort), cmp.Compare(a.Proto, b.Proto), a.HostIP.Compare(b.HostIP))
		})
		out = append(out, ct)
	}
	return out, nil
}
