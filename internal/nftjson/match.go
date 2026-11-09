package nftjson

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Santaniel0/fwreach/internal/netpkt"
	"github.com/Santaniel0/fwreach/internal/ruleset"
)

// value is one element on the right side of a match: a name, a number,
// an address prefix or a numeric range.
type value struct {
	str      string
	num      uint64
	isNum    bool
	prefix   netip.Prefix
	from, to uint64
	isRange  bool
}

func (p *parser) values(raw json.RawMessage, rj *ruleJSON, depth int) ([]value, bool) {
	if depth > 4 {
		return nil, false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if name, ok := strings.CutPrefix(s, "@"); ok {
			var out []value
			for _, e := range p.sets[rj.Family+" "+rj.Table+" "+name] {
				vs, ok := p.values(e, rj, depth+1)
				if !ok {
					return nil, false
				}
				out = append(out, vs...)
			}
			return out, true
		}
		v := value{str: s}
		if a, err := netip.ParseAddr(s); err == nil {
			v.prefix = netip.PrefixFrom(a, a.BitLen())
		}
		return []value{v}, true
	}
	var n uint64
	if json.Unmarshal(raw, &n) == nil {
		return []value{{num: n, isNum: true}}, true
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) == nil {
		var out []value
		for _, e := range list {
			vs, ok := p.values(e, rj, depth+1)
			if !ok {
				return nil, false
			}
			out = append(out, vs...)
		}
		return out, true
	}
	var obj struct {
		Set    []json.RawMessage `json:"set"`
		Range  []uint64          `json:"range"`
		Prefix *struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
		Elem *struct {
			Val json.RawMessage `json:"val"`
		} `json:"elem"`
	}
	if json.Unmarshal(raw, &obj) != nil {
		return nil, false
	}
	switch {
	case obj.Set != nil:
		return p.values(mustMarshal(obj.Set), rj, depth+1)
	case len(obj.Range) == 2:
		return []value{{from: obj.Range[0], to: obj.Range[1], isRange: true}}, true
	case obj.Prefix != nil:
		pr, err := netip.ParsePrefix(obj.Prefix.Addr + "/" + strconv.Itoa(obj.Prefix.Len))
		if err != nil {
			return nil, false
		}
		return []value{{prefix: pr.Masked()}}, true
	case obj.Elem != nil:
		return p.values(obj.Elem.Val, rj, depth+1)
	}
	return nil, false
}

func mustMarshal(v []json.RawMessage) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// match compiles one match expression. Anything outside the supported
// subset becomes a single UnknownMatch carrying the rendered expression.
func (p *parser) match(m matchJSON, rj *ruleJSON) (string, []ruleset.Match) {
	left := render(m.Left)
	op := ""
	if m.Op == "!=" {
		op = "!= "
	}
	text := left + " " + op + renderValue(m.Right, strings.HasSuffix(left, "ifname"))
	vals, ok := p.values(m.Right, rj, 0)
	if !ok || len(vals) == 0 || (m.Op != "==" && m.Op != "!=" && m.Op != "in") {
		return text, []ruleset.Match{ruleset.UnknownMatch{What: text}}
	}
	ms, ok := lower(left, m.Left, vals, m.Op == "!=")
	if !ok {
		return text, []ruleset.Match{ruleset.UnknownMatch{What: text}}
	}
	return text, ms
}

func lower(left string, leftRaw json.RawMessage, vals []value, neg bool) ([]ruleset.Match, bool) {
	switch left {
	case "ip saddr", "ip daddr", "ip6 saddr", "ip6 daddr", "ct original daddr", "ct original ip daddr", "ct original ip6 daddr":
		m := ruleset.AddrMatch{Dir: ruleset.DirSrc, Negate: neg, OrigDst: strings.HasPrefix(left, "ct ")}
		if strings.HasSuffix(left, "daddr") {
			m.Dir = ruleset.DirDst
		}
		for _, v := range vals {
			if !v.prefix.IsValid() {
				return nil, false
			}
			m.Prefixes = append(m.Prefixes, v.prefix)
		}
		m.Family = netpkt.FamilyOf(m.Prefixes[0].Addr())
		return []ruleset.Match{m}, true
	case "tcp dport", "tcp sport", "udp dport", "udp sport", "th dport", "th sport", "ct original proto-dst":
		rs, ok := ranges(vals)
		if !ok {
			return nil, false
		}
		pm := ruleset.PortMatch{Dir: ruleset.DirDst, Ranges: rs, Negate: neg, OrigDst: strings.HasPrefix(left, "ct ")}
		if strings.HasSuffix(left, "sport") {
			pm.Dir = ruleset.DirSrc
		}
		protos := []netpkt.Proto{netpkt.ProtoTCP, netpkt.ProtoUDP}
		switch {
		case strings.HasPrefix(left, "tcp "):
			protos = protos[:1]
		case strings.HasPrefix(left, "udp "):
			protos = protos[1:]
		case pm.OrigDst:
			return []ruleset.Match{pm}, true
		}
		return []ruleset.Match{ruleset.ProtoMatch{Protos: protos}, pm}, true
	case "iifname", "oifname":
		var ms []ruleset.Match
		for _, v := range vals {
			name, wild := strings.CutSuffix(v.str, "*")
			ms = append(ms, ruleset.IfaceMatch{Out: left == "oifname", Name: name, Pattern: wild, Negate: neg})
		}
		if neg || len(ms) == 1 {
			return ms, true
		}
		return []ruleset.Match{ruleset.AnyMatch(ms)}, true
	case "meta l4proto":
		m := ruleset.ProtoMatch{Negate: neg}
		for _, v := range vals {
			pr, err := netpkt.ParseProto(v.str)
			if v.isNum {
				pr, err = netpkt.Proto(v.num), nil
			}
			if err != nil {
				return nil, false
			}
			m.Protos = append(m.Protos, pr)
		}
		return []ruleset.Match{m}, true
	case "meta nfproto":
		if len(vals) != 1 || (vals[0].str != "ipv4" && vals[0].str != "ipv6") {
			return nil, false
		}
		fam := netpkt.IPv4
		if (vals[0].str == "ipv6") != neg {
			fam = netpkt.IPv6
		}
		return []ruleset.Match{ruleset.FamilyMatch{Family: fam}}, true
	case "meta mark":
		if len(vals) != 1 || !vals[0].isNum {
			return nil, false
		}
		m := ruleset.MarkMatch{Value: uint32(vals[0].num), Mask: 0xffffffff, Negate: neg}
		var e exprJSON
		if json.Unmarshal(leftRaw, &e) == nil && len(e.And) == 2 {
			if json.Unmarshal(e.And[1], &m.Mask) != nil {
				return nil, false
			}
		}
		return []ruleset.Match{m}, true
	case "ct state", "ct status":
		m := ruleset.CtStateMatch{Negate: neg}
		for _, v := range vals {
			st, ok := ruleset.ParseCtState(v.str)
			if !ok || (left == "ct status" && st != ruleset.CtDNAT) {
				return nil, false
			}
			m.States |= st
		}
		return []ruleset.Match{m}, true
	case "fib daddr type", "fib saddr type":
		m := ruleset.AddrTypeMatch{Dir: ruleset.DirDst, Negate: neg}
		if left == "fib saddr type" {
			m.Dir = ruleset.DirSrc
		}
		for _, v := range vals {
			switch v.str {
			case "local":
				m.Types |= netpkt.AddrLocal
			case "unicast":
				m.Types |= netpkt.AddrUnicast
			case "broadcast":
				m.Types |= netpkt.AddrBroadcast
			case "multicast":
				m.Types |= netpkt.AddrMulticast
			default:
				return nil, false
			}
		}
		return []ruleset.Match{m}, true
	}
	return nil, false
}

func ranges(vals []value) ([]ruleset.PortRange, bool) {
	var out []ruleset.PortRange
	for _, v := range vals {
		switch {
		case v.isNum && v.num <= 65535:
			out = append(out, ruleset.PortRange{From: uint16(v.num), To: uint16(v.num)})
		case v.isRange && v.to <= 65535:
			out = append(out, ruleset.PortRange{From: uint16(v.from), To: uint16(v.to)})
		default:
			if n, err := strconv.ParseUint(v.str, 10, 16); err == nil {
				out = append(out, ruleset.PortRange{From: uint16(n), To: uint16(n)})
				continue
			}
			return nil, false
		}
	}
	return out, true
}

// render prints an expression the way `nft list ruleset` would.
func render(raw json.RawMessage) string {
	var e exprJSON
	if json.Unmarshal(raw, &e) != nil {
		return strings.Trim(string(raw), `"`)
	}
	switch {
	case e.Payload != nil:
		return e.Payload.Protocol + " " + e.Payload.Field
	case e.Meta != nil:
		switch e.Meta.Key {
		case "iifname", "oifname", "iif", "oif":
			return e.Meta.Key
		}
		return "meta " + e.Meta.Key
	case e.Ct != nil:
		if e.Ct.Dir != "" {
			return "ct " + e.Ct.Dir + " " + e.Ct.Key
		}
		return "ct " + e.Ct.Key
	case e.Fib != nil:
		return "fib " + strings.Join(e.Fib.Flags, " ") + " " + e.Fib.Result
	case len(e.And) == 2:
		return render(e.And[0])
	}
	return strings.Trim(string(raw), `"`)
}

func renderValue(raw json.RawMessage, quote bool) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if quote && !strings.HasPrefix(s, "@") {
			return strconv.Quote(s)
		}
		return s
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) == nil {
		var parts []string
		for _, e := range list {
			parts = append(parts, renderValue(e, quote))
		}
		return strings.Join(parts, ",")
	}
	var obj struct {
		Set    []json.RawMessage `json:"set"`
		Range  []json.RawMessage `json:"range"`
		Prefix *struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		switch {
		case obj.Set != nil:
			var parts []string
			for _, e := range obj.Set {
				parts = append(parts, renderValue(e, quote))
			}
			return "{ " + strings.Join(parts, ", ") + " }"
		case len(obj.Range) == 2:
			return renderValue(obj.Range[0], quote) + "-" + renderValue(obj.Range[1], quote)
		case obj.Prefix != nil:
			return obj.Prefix.Addr + "/" + strconv.Itoa(obj.Prefix.Len)
		}
	}
	return string(raw)
}
