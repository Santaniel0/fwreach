package sim

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/Santaniel0/fwreach/internal/netpkt"
	"github.com/Santaniel0/fwreach/internal/ruleset"
)

var (
	hostIP = netip.MustParseAddr("203.0.113.10")
	ctrIP  = netip.MustParseAddr("172.18.0.3")
	host   = &netpkt.Host{Ifaces: []netpkt.Iface{
		{Name: "lo", Loopback: true, Addrs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}},
		{Name: "eth0", Addrs: []netip.Prefix{netip.MustParsePrefix("203.0.113.10/24")}},
		{Name: "br-app", Addrs: []netip.Prefix{netip.MustParsePrefix("172.18.0.1/16")}},
	}}
)

func base(name string, hook netpkt.Hook, kind ruleset.ChainKind, prio int, pol ruleset.Verdict, rules ...ruleset.Rule) *ruleset.Chain {
	for i := range rules {
		rules[i].Pos = i + 1
	}
	return &ruleset.Chain{Name: name, Base: &ruleset.BaseChain{Hook: hook, Kind: kind, Priority: prio, Policy: pol}, Rules: rules}
}

func chain(name string, rules ...ruleset.Rule) *ruleset.Chain {
	for i := range rules {
		rules[i].Pos = i + 1
	}
	return &ruleset.Chain{Name: name, Rules: rules}
}

func table(name string, chains ...*ruleset.Chain) *ruleset.Table {
	return &ruleset.Table{Family: ruleset.FamilyIP, Name: name, Source: ruleset.SourceNftables, Chains: chains}
}

func rule(text string, a ruleset.Action, ms ...ruleset.Match) ruleset.Rule {
	return ruleset.Rule{Text: text, Matches: ms, Action: a}
}

func verdict(v ruleset.Verdict) ruleset.Action {
	return ruleset.Action{Kind: ruleset.ActVerdict, Verdict: v}
}

func jump(target string) ruleset.Action { return ruleset.Action{Kind: ruleset.ActJump, Target: target} }

func dport(p uint16) ruleset.Match {
	return ruleset.PortMatch{Dir: ruleset.DirDst, Ranges: []ruleset.PortRange{{From: p, To: p}}}
}

func dnatTo(addr netip.Addr, port uint16) ruleset.Action {
	return ruleset.Action{Kind: ruleset.ActDNAT, DNATAddr: addr, DNATPort: port}
}

func probe(port uint16) netpkt.Packet {
	return netpkt.NewInbound(netpkt.ProtoTCP, netip.MustParseAddr("198.51.100.7"), hostIP, port, "eth0")
}

type want struct {
	verdict ruleset.Verdict
	local   bool
	byChain string
	dst     netip.AddrPort
}

func TestSemantics(t *testing.T) {
	A, D := ruleset.Accept, ruleset.Drop
	cases := []struct {
		name  string
		rs    []*ruleset.Table
		port  uint16
		wants []want
	}{
		{
			name: "accept is not final across base chains",
			rs: []*ruleset.Table{
				table("a", base("in", netpkt.Input, ruleset.KindFilter, -10, A, rule("accept", verdict(A)))),
				table("b", base("in", netpkt.Input, ruleset.KindFilter, 0, A, rule("tcp dport 22 drop", verdict(D), dport(22)))),
			},
			port:  22,
			wants: []want{{verdict: D, byChain: "in"}},
		},
		{
			name: "drop is final, later chains never run",
			rs: []*ruleset.Table{
				table("b", base("late", netpkt.Input, ruleset.KindFilter, 10, A, rule("accept", verdict(A)))),
				table("a", base("early", netpkt.Input, ruleset.KindFilter, -10, A, rule("drop", verdict(D)))),
			},
			port:  22,
			wants: []want{{verdict: D, byChain: "early"}},
		},
		{
			name:  "policy drop when nothing matches",
			rs:    []*ruleset.Table{table("f", base("in", netpkt.Input, ruleset.KindFilter, 0, D, rule("tcp dport 22 accept", verdict(A), dport(22))))},
			port:  80,
			wants: []want{{verdict: D, byChain: "in"}},
		},
		{
			name: "return resumes the calling chain",
			rs: []*ruleset.Table{table("f",
				base("in", netpkt.Input, ruleset.KindFilter, 0, D, rule("jump user", jump("user")), rule("tcp dport 80 accept", verdict(A), dport(80))),
				chain("user", rule("tcp dport 80 return", ruleset.Action{Kind: ruleset.ActReturn}, dport(80)), rule("drop", verdict(D))),
			)},
			port:  80,
			wants: []want{{verdict: A, local: true}},
		},
		{
			name: "goto does not come back to the caller",
			rs: []*ruleset.Table{table("f",
				base("in", netpkt.Input, ruleset.KindFilter, 0, D, rule("goto user", ruleset.Action{Kind: ruleset.ActGoto, Target: "user"}), rule("accept", verdict(A))),
				chain("user"),
			)},
			port:  80,
			wants: []want{{verdict: D, byChain: "in"}},
		},
		{
			name: "dnat sends the packet to forward, input rules never see it",
			rs: []*ruleset.Table{table("f",
				base("pre", netpkt.Prerouting, ruleset.KindNAT, -100, A, rule("dnat", dnatTo(ctrIP, 5432), dport(5432))),
				base("in", netpkt.Input, ruleset.KindFilter, 0, D, rule("tcp dport 5432 drop", verdict(D), dport(5432))),
				base("fwd", netpkt.Forward, ruleset.KindFilter, 0, A),
			)},
			port:  5432,
			wants: []want{{verdict: A, dst: netip.AddrPortFrom(ctrIP, 5432)}},
		},
		{
			name: "first dnat on a hook wins",
			rs: []*ruleset.Table{
				table("late", base("pre", netpkt.Prerouting, ruleset.KindNAT, -90, A, rule("dnat .9", dnatTo(netip.MustParseAddr("172.18.0.9"), 1)))),
				table("early", base("pre", netpkt.Prerouting, ruleset.KindNAT, -100, A, rule("dnat .3", dnatTo(ctrIP, 8080)))),
			},
			port:  3000,
			wants: []want{{verdict: A, dst: netip.AddrPortFrom(ctrIP, 8080)}},
		},
		{
			name: "mark set in an early chain is seen by a later one",
			rs: []*ruleset.Table{
				table("user", base("fwd", netpkt.Forward, ruleset.KindFilter, -1, A,
					rule("meta mark set 1", ruleset.Action{Kind: ruleset.ActSetMark, Mark: 1, MarkMask: 0xffffffff}))),
				table("docker", base("pre", netpkt.Prerouting, ruleset.KindNAT, -100, A, rule("dnat", dnatTo(ctrIP, 80))),
					base("fwd", netpkt.Forward, ruleset.KindFilter, 0, A,
						rule("mark 1 accept", verdict(A), ruleset.MarkMatch{Value: 1, Mask: 1}), rule("drop", verdict(D)))),
			},
			port:  80,
			wants: []want{{verdict: A, dst: netip.AddrPortFrom(ctrIP, 80)}},
		},
		{
			name: "ip6 table does not touch ipv4 packets",
			rs: []*ruleset.Table{{Family: ruleset.FamilyIP6, Name: "f", Chains: []*ruleset.Chain{
				base("in", netpkt.Input, ruleset.KindFilter, 0, D)}}},
			port:  22,
			wants: []want{{verdict: A, local: true}},
		},
		{
			name:  "dnat to an address with no connected route is not delivered",
			rs:    []*ruleset.Table{table("n", base("pre", netpkt.Prerouting, ruleset.KindNAT, -100, A, rule("dnat", dnatTo(netip.MustParseAddr("192.0.2.50"), 80))))},
			port:  80,
			wants: []want{{verdict: A}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := New(&ruleset.Ruleset{Tables: tc.rs}, host)
			outs, err := p.Simulate(context.Background(), probe(tc.port))
			if err != nil {
				t.Fatal(err)
			}
			if len(outs) != len(tc.wants) {
				t.Fatalf("got %d outcomes, want %d: %+v", len(outs), len(tc.wants), outs)
			}
			for i, w := range tc.wants {
				o := outs[i]
				if !o.Decided || o.Verdict != w.verdict || o.Local != w.local {
					t.Errorf("outcome %d: decided=%v verdict=%v local=%v, want %v local=%v", i, o.Decided, o.Verdict, o.Local, w.verdict, w.local)
				}
				if w.byChain != "" && (o.By == nil || o.By.Chain != w.byChain) {
					t.Errorf("outcome %d decided by %+v, want chain %q", i, o.By, w.byChain)
				}
				if w.dst.IsValid() && (netip.AddrPortFrom(o.Packet.Dst, o.Packet.DstPort) != w.dst || !o.Delivered()) {
					t.Errorf("outcome %d delivered to %v:%d (delivered=%v), want %v", i, o.Packet.Dst, o.Packet.DstPort, o.Delivered(), w.dst)
				}
			}
		})
	}
}

func TestUnknownMatchForks(t *testing.T) {
	rs := &ruleset.Ruleset{Tables: []*ruleset.Table{table("f",
		base("in", netpkt.Input, ruleset.KindFilter, 0, ruleset.Accept,
			rule("-m recent --rcheck -j DROP", verdict(ruleset.Drop), ruleset.UnknownMatch{What: "recent"})))}}
	outs, err := New(rs, host).Simulate(context.Background(), probe(22))
	if err != nil {
		t.Fatal(err)
	}
	var accepted, dropped int
	for _, o := range outs {
		if len(o.Assumed) != 1 {
			t.Fatalf("each branch must record its assumption, got %+v", o.Assumed)
		}
		switch {
		case o.Delivered() && !o.Assumed[0].Matched:
			accepted++
		case o.Verdict == ruleset.Drop && o.Assumed[0].Matched:
			dropped++
		}
	}
	if accepted != 1 || dropped != 1 {
		t.Fatalf("want one accepted and one dropped branch, got %d/%d", accepted, dropped)
	}
}

func TestForkBudgetEndsUndecided(t *testing.T) {
	var rules []ruleset.Rule
	for range 40 {
		rules = append(rules, rule("unknown mark", ruleset.Action{Kind: ruleset.ActSetMark, Mark: 1, MarkMask: 1}, ruleset.UnknownMatch{What: "x"}))
	}
	rs := &ruleset.Ruleset{Tables: []*ruleset.Table{table("f", base("in", netpkt.Input, ruleset.KindFilter, 0, ruleset.Accept, rules...))}}
	outs, err := New(rs, host).Simulate(context.Background(), probe(22))
	if err != nil {
		t.Fatal(err)
	}
	undecided := 0
	for _, o := range outs {
		if !o.Decided {
			undecided++
		}
	}
	if undecided == 0 || len(outs) > 2*maxForks+2 {
		t.Fatalf("want a bounded result with undecided branches, got %d outcomes, %d undecided", len(outs), undecided)
	}
}

func TestSimulateHonorsCancellation(t *testing.T) {
	rs := &ruleset.Ruleset{Tables: []*ruleset.Table{table("f", base("in", netpkt.Input, ruleset.KindFilter, 0, ruleset.Accept))}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(rs, host).Simulate(ctx, probe(22)); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}
