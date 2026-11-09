// Package ruleset is the intermediate representation both frontends
// (iptables-save and nft JSON) compile into. The simulator only sees this.
package ruleset

import (
	"fmt"
	"net/netip"
	"strconv"

	"github.com/Santaniel0/fwreach/internal/netpkt"
)

// Source says where a table came from. Legacy iptables and nftables tables
// can coexist in one kernel, and both run on the same hooks.
type Source uint8

const (
	SourceIPTablesLegacy Source = iota + 1
	SourceIPTablesNft
	SourceNftables
)

func (s Source) String() string {
	switch s {
	case SourceIPTablesLegacy:
		return "iptables-legacy"
	case SourceIPTablesNft:
		return "iptables-nft"
	case SourceNftables:
		return "nftables"
	}
	return "source(" + strconv.Itoa(int(s)) + ")"
}

// IsIPTables reports whether the table was written through the iptables CLI.
func (s Source) IsIPTables() bool { return s == SourceIPTablesLegacy || s == SourceIPTablesNft }

// TableFamily is the nftables family of a table; iptables tables are ip or ip6.
type TableFamily uint8

const (
	FamilyIP TableFamily = iota + 1
	FamilyIP6
	FamilyInet
)

func (f TableFamily) String() string {
	switch f {
	case FamilyIP:
		return "ip"
	case FamilyIP6:
		return "ip6"
	case FamilyInet:
		return "inet"
	}
	return "family(" + strconv.Itoa(int(f)) + ")"
}

// Covers reports whether a table of this family sees packets of fam.
func (f TableFamily) Covers(fam netpkt.Family) bool {
	return f == FamilyInet || (f == FamilyIP && fam == netpkt.IPv4) || (f == FamilyIP6 && fam == netpkt.IPv6)
}

// ChainKind is the base chain type. NAT chains follow different rules:
// only the first one to translate a connection on a hook takes effect.
type ChainKind uint8

const (
	KindFilter ChainKind = iota + 1
	KindNAT
	KindRoute
)

func (k ChainKind) String() string {
	switch k {
	case KindFilter:
		return "filter"
	case KindNAT:
		return "nat"
	case KindRoute:
		return "route"
	}
	return "kind(" + strconv.Itoa(int(k)) + ")"
}

// Verdict is a final decision about a packet.
type Verdict uint8

const (
	Accept Verdict = iota + 1
	Drop
	Reject
)

func (v Verdict) String() string {
	switch v {
	case Accept:
		return "accept"
	case Drop:
		return "drop"
	case Reject:
		return "reject"
	}
	return "verdict(" + strconv.Itoa(int(v)) + ")"
}

// Ruleset is everything loaded from one host snapshot.
type Ruleset struct {
	Tables []*Table
}

// Table groups chains. Chains keeps declaration order for stable output.
type Table struct {
	Family TableFamily
	Name   string
	Source Source
	Chains []*Chain
}

// ID renders the table the way nft does, e.g. "ip filter".
func (t *Table) ID() string { return t.Family.String() + " " + t.Name }

// Chain looks up a chain by name.
func (t *Table) Chain(name string) *Chain {
	for _, c := range t.Chains {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// Chain is a list of rules; Base is set for chains attached to a hook.
type Chain struct {
	Name  string
	Base  *BaseChain
	Rules []Rule
}

// BaseChain describes how a chain is attached to a hook.
type BaseChain struct {
	Hook     netpkt.Hook
	Kind     ChainKind
	Priority int
	Policy   Verdict
}

// Rule is one rule. Pos is the 1-based position shown by iptables -L
// --line-numbers or the order in nft list output.
type Rule struct {
	Pos     int
	Text    string
	Matches []Match
	Action  Action
}

// ActionKind enumerates what a rule does when it matches.
type ActionKind uint8

const (
	ActContinue ActionKind = iota + 1 // log, counter: no effect on the path
	ActVerdict
	ActReturn
	ActJump
	ActGoto
	ActDNAT
	ActRedirect
	ActSetMark
	ActUnknown
)

// Action is what happens when all matches of a rule hold.
type Action struct {
	Kind     ActionKind
	Verdict  Verdict
	Target   string
	DNATAddr netip.Addr
	DNATPort uint16
	Mark     uint32
	MarkMask uint32
	What     string
}

// Terminal reports whether the action can change the packet's fate or path.
func (a Action) Terminal() bool { return a.Kind != ActContinue }

// Match is one condition of a rule. Eval must never guess: anything it
// cannot decide from the packet and host state is Unknown.
type Match interface {
	Eval(p *netpkt.Packet, h *netpkt.Host) netpkt.Tristate
}

// EvalAll ANDs the matches: a single No wins over any number of Unknowns.
func EvalAll(ms []Match, p *netpkt.Packet, h *netpkt.Host) netpkt.Tristate {
	res := netpkt.Yes
	for _, m := range ms {
		switch m.Eval(p, h) {
		case netpkt.No:
			return netpkt.No
		case netpkt.Unknown:
			res = netpkt.Unknown
		}
	}
	return res
}

// Dir selects the source or destination side of a packet.
type Dir uint8

const (
	DirSrc Dir = iota + 1
	DirDst
)

// IfaceMatch matches the input or output interface. A trailing '+'
// (iptables) or '*' (nft) is a prefix wildcard.
type IfaceMatch struct {
	Out     bool
	Name    string
	Negate  bool
	Pattern bool
}

func (m IfaceMatch) Eval(p *netpkt.Packet, _ *netpkt.Host) netpkt.Tristate {
	name := p.InIface
	if m.Out {
		name = p.OutIface
	}
	ok := name == m.Name
	if m.Pattern {
		ok = len(name) >= len(m.Name) && name[:len(m.Name)] == m.Name
	}
	return netpkt.Bool(ok != m.Negate)
}

// AddrMatch matches the source or destination address against prefixes.
// A packet of the other family never matches, negated or not, the same way
// "ip saddr != x" does not match IPv6 traffic in an inet table.
type AddrMatch struct {
	Dir      Dir
	Family   netpkt.Family
	Prefixes []netip.Prefix
	Negate   bool
	OrigDst  bool // conntrack original destination instead of the current one
}

func (m AddrMatch) Eval(p *netpkt.Packet, _ *netpkt.Host) netpkt.Tristate {
	if p.Family != m.Family {
		return netpkt.No
	}
	addr := p.Src
	switch {
	case m.OrigDst:
		addr = p.OrigDst
	case m.Dir == DirDst:
		addr = p.Dst
	}
	in := false
	for _, pr := range m.Prefixes {
		if pr.Contains(addr) {
			in = true
			break
		}
	}
	return netpkt.Bool(in != m.Negate)
}

// FamilyMatch restricts a rule to one IP version (nft meta nfproto).
type FamilyMatch struct{ Family netpkt.Family }

func (m FamilyMatch) Eval(p *netpkt.Packet, _ *netpkt.Host) netpkt.Tristate {
	return netpkt.Bool(p.Family == m.Family)
}

// ProtoMatch matches the layer 4 protocol against a set.
type ProtoMatch struct {
	Protos []netpkt.Proto
	Negate bool
}

func (m ProtoMatch) Eval(p *netpkt.Packet, _ *netpkt.Host) netpkt.Tristate {
	in := false
	for _, pr := range m.Protos {
		if pr == p.Proto {
			in = true
		}
	}
	return netpkt.Bool(in != m.Negate)
}

// PortRange is an inclusive port interval.
type PortRange struct{ From, To uint16 }

func (r PortRange) String() string {
	if r.From == r.To {
		return strconv.Itoa(int(r.From))
	}
	return fmt.Sprintf("%d-%d", r.From, r.To)
}

// PortMatch matches a transport port. OrigDst uses the port the client
// connected to before DNAT, like --ctorigdstport or ct original proto-dst.
type PortMatch struct {
	Dir     Dir
	Ranges  []PortRange
	Negate  bool
	OrigDst bool
}

func (m PortMatch) Eval(p *netpkt.Packet, _ *netpkt.Host) netpkt.Tristate {
	if p.Proto != netpkt.ProtoTCP && p.Proto != netpkt.ProtoUDP {
		return netpkt.No
	}
	port := p.SrcPort
	switch {
	case m.OrigDst:
		port = p.OrigDstPort
	case m.Dir == DirDst:
		port = p.DstPort
	}
	in := false
	for _, r := range m.Ranges {
		if port >= r.From && port <= r.To {
			in = true
		}
	}
	return netpkt.Bool(in != m.Negate)
}

// CtState is a conntrack state bit set, including the virtual DNAT/SNAT states.
type CtState uint8

const (
	CtNew CtState = 1 << iota
	CtEstablished
	CtRelated
	CtInvalid
	CtUntracked
	CtDNAT
	CtSNAT
)

// ParseCtState parses one state name as used by iptables and nft.
func ParseCtState(s string) (CtState, bool) {
	switch s {
	case "new", "NEW":
		return CtNew, true
	case "established", "ESTABLISHED":
		return CtEstablished, true
	case "related", "RELATED":
		return CtRelated, true
	case "invalid", "INVALID":
		return CtInvalid, true
	case "untracked", "UNTRACKED":
		return CtUntracked, true
	case "dnat", "DNAT":
		return CtDNAT, true
	case "snat", "SNAT":
		return CtSNAT, true
	}
	return 0, false
}

// CtStateMatch matches conntrack state. The simulated packet is always the
// first of a connection, so it is NEW, plus DNAT once translated.
type CtStateMatch struct {
	States CtState
	Negate bool
}

func (m CtStateMatch) Eval(p *netpkt.Packet, _ *netpkt.Host) netpkt.Tristate {
	have := CtNew
	if p.DNATed {
		have |= CtDNAT
	}
	return netpkt.Bool((m.States&have != 0) != m.Negate)
}

// AddrTypeMatch is iptables -m addrtype or nft fib ... type.
type AddrTypeMatch struct {
	Dir    Dir
	Types  netpkt.AddrType
	Negate bool
}

func (m AddrTypeMatch) Eval(p *netpkt.Packet, h *netpkt.Host) netpkt.Tristate {
	addr := p.Dst
	if m.Dir == DirSrc {
		addr = p.Src
	}
	return netpkt.Bool((h.TypeOf(addr)&m.Types != 0) != m.Negate)
}

// MarkMatch matches the packet mark under a mask.
type MarkMatch struct {
	Value, Mask uint32
	Negate      bool
}

func (m MarkMatch) Eval(p *netpkt.Packet, _ *netpkt.Host) netpkt.Tristate {
	return netpkt.Bool((p.Mark&m.Mask == m.Value) != m.Negate)
}

// AnyMatch holds when any of its matches does, like an nft anonymous set
// of interface names.
type AnyMatch []Match

func (m AnyMatch) Eval(p *netpkt.Packet, h *netpkt.Host) netpkt.Tristate {
	res := netpkt.No
	for _, sub := range m {
		switch sub.Eval(p, h) {
		case netpkt.Yes:
			return netpkt.Yes
		case netpkt.Unknown:
			res = netpkt.Unknown
		}
	}
	return res
}

// UnknownMatch stands for a match fwreach does not model.
type UnknownMatch struct{ What string }

func (UnknownMatch) Eval(*netpkt.Packet, *netpkt.Host) netpkt.Tristate { return netpkt.Unknown }

// FixedMatch has the same answer for every packet fwreach simulates: an
// ICMP type never matches a TCP SYN, "--ctdir ORIGINAL" always does.
type FixedMatch struct {
	Matches bool
	Why     string
}

func (m FixedMatch) Eval(*netpkt.Packet, *netpkt.Host) netpkt.Tristate { return netpkt.Bool(m.Matches) }

// HasUnknown reports whether a rule contains a match or action fwreach
// cannot evaluate and that could change a packet's path. A log rule with
// a rate limit cannot.
func (r Rule) HasUnknown() bool {
	if !r.Action.Terminal() {
		return false
	}
	if r.Action.Kind == ActUnknown {
		return true
	}
	for _, m := range r.Matches {
		if _, ok := m.(UnknownMatch); ok {
			return true
		}
	}
	return false
}
