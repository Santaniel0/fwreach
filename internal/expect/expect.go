// Package expect parses the expectations file: the list of inbound
// exposures the operator intends. Anything netfilter allows beyond it is a
// violation.
//
//	# comment
//	allow tcp/22 from any
//	allow tcp/80,443 from any
//	allow tcp/9100 from 10.0.0.0/8, 192.168.0.0/16
package expect

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Santaniel0/fwreach/internal/netpkt"
	"github.com/Santaniel0/fwreach/internal/ruleset"
)

// ErrSyntax marks a malformed expectations file.
var ErrSyntax = errors.New("expectations syntax error")

// maxListedPorts limits how many ports of a range are probed explicitly.
const maxListedPorts = 64

// Rule is one "allow" line.
type Rule struct {
	Line  int
	Proto netpkt.Proto
	Ports []ruleset.PortRange
	From  []netip.Prefix
}

// Set is a parsed expectations file.
type Set struct {
	Rules []Rule
}

// ProtoPort identifies a transport endpoint.
type ProtoPort struct {
	Proto netpkt.Proto
	Port  uint16
}

func (pp ProtoPort) String() string { return pp.Proto.String() + "/" + strconv.Itoa(int(pp.Port)) }

// Parse reads an expectations file.
func Parse(r io.Reader) (*Set, error) {
	s := &Set{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		if strings.TrimSpace(line) == "" {
			continue
		}
		rule, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		rule.Line = n
		s.Rules = append(s.Rules, rule)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read expectations: %w", err)
	}
	return s, nil
}

func parseLine(line string) (Rule, error) {
	f := strings.Fields(line)
	if len(f) < 4 || f[0] != "allow" || f[2] != "from" {
		return Rule{}, fmt.Errorf("%w: want \"allow <proto>/<ports> from <any|cidr,...>\", got %q", ErrSyntax, strings.TrimSpace(line))
	}
	protoS, portsS, ok := strings.Cut(f[1], "/")
	if !ok {
		return Rule{}, fmt.Errorf("%w: %q needs proto/port", ErrSyntax, f[1])
	}
	proto, err := netpkt.ParseProto(protoS)
	if err != nil || (proto != netpkt.ProtoTCP && proto != netpkt.ProtoUDP) {
		return Rule{}, fmt.Errorf("%w: protocol %q, want tcp or udp", ErrSyntax, protoS)
	}
	rule := Rule{Proto: proto}
	for _, ps := range strings.Split(portsS, ",") {
		from, to, isRange := strings.Cut(ps, "-")
		a, err1 := strconv.ParseUint(from, 10, 16)
		b, err2 := a, error(nil)
		if isRange {
			b, err2 = strconv.ParseUint(to, 10, 16)
		}
		if err1 != nil || err2 != nil || b < a || a == 0 {
			return Rule{}, fmt.Errorf("%w: port %q", ErrSyntax, ps)
		}
		rule.Ports = append(rule.Ports, ruleset.PortRange{From: uint16(a), To: uint16(b)})
	}
	srcs := strings.FieldsFunc(strings.Join(f[3:], " "), func(r rune) bool { return r == ',' || r == ' ' })
	for _, src := range srcs {
		if src == "any" {
			rule.From = append(rule.From, netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"))
			continue
		}
		p, err := netip.ParsePrefix(src)
		if err != nil {
			a, aerr := netip.ParseAddr(src)
			if aerr != nil {
				return Rule{}, fmt.Errorf("%w: source %q", ErrSyntax, src)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		rule.From = append(rule.From, p.Masked())
	}
	if len(rule.From) == 0 {
		return Rule{}, fmt.Errorf("%w: no sources after \"from\"", ErrSyntax)
	}
	return rule, nil
}

// Allows reports whether traffic from src to proto/port is expected.
func (s *Set) Allows(pp ProtoPort, src netip.Addr) bool {
	for _, r := range s.Rules {
		if r.Proto != pp.Proto || !inRanges(r.Ports, pp.Port) {
			continue
		}
		for _, p := range r.From {
			if p.Contains(src) {
				return true
			}
		}
	}
	return false
}

// Prefixes returns every source prefix mentioned, so the caller can make
// them class boundaries and test one representative per class.
func (s *Set) Prefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, r := range s.Rules {
		out = append(out, r.From...)
	}
	return out
}

// Endpoints lists the ports the file names, skipping large ranges.
func (s *Set) Endpoints() []ProtoPort {
	var out []ProtoPort
	for _, r := range s.Rules {
		for _, pr := range r.Ports {
			if int(pr.To)-int(pr.From) >= maxListedPorts {
				continue
			}
			for p := int(pr.From); p <= int(pr.To); p++ {
				out = append(out, ProtoPort{Proto: r.Proto, Port: uint16(p)})
			}
		}
	}
	return out
}

func inRanges(rs []ruleset.PortRange, port uint16) bool {
	for _, r := range rs {
		if port >= r.From && port <= r.To {
			return true
		}
	}
	return false
}
