package exposure

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Santaniel0/fwreach/internal/iptables"
	"github.com/Santaniel0/fwreach/internal/netpkt"
	"github.com/Santaniel0/fwreach/internal/ruleset"
	"github.com/Santaniel0/fwreach/internal/sim"
)

// The documents each hint follows. A hint is only printed after the rule
// it suggests has been added to the loaded ruleset and the same packet,
// simulated again, no longer gets through.
const (
	// "Match the original IP and ports for requests": DOCKER-USER sees
	// packets after DNAT, so the published port must be matched through
	// conntrack.
	docDockerUser = "https://docs.docker.com/engine/network/firewall-iptables/#match-the-original-ip-and-ports-for-requests"
	// Publishing to 127.0.0.1 keeps the port off external interfaces.
	docLoopback = "https://docs.docker.com/engine/network/port-publishing/"
	// With the nftables backend there is no DOCKER-USER; rules go in your
	// own table on the forward hook, and a drop there is final.
	docNftables = "https://docs.docker.com/engine/network/firewall-nftables/"
)

// notes explain why rules the operator may rely on did not stop a packet
// that DNAT moved to the forward hook.
func (a *analyzer) notes(ctx context.Context, ex *Example) ([]string, error) {
	o := ex.Outcome
	if o.DNAT == nil {
		return nil, nil
	}
	var notes []string
	in, err := a.pipe.RunHook(ctx, netpkt.Input, ex.Sent)
	if err != nil {
		return nil, err
	}
	if by, ok := droppedByAll(in); ok {
		notes = append(notes, fmt.Sprintf("%s would drop this packet on the input path, but DNAT sent it to forward, so input rules never see it", stepRef(by)))
	}
	if o.Packet.DstPort != o.Packet.OrigDstPort {
		restored := o.Packet
		restored.DstPort = o.Packet.OrigDstPort
		fwd, err := a.pipe.RunHook(ctx, netpkt.Forward, restored)
		if err != nil {
			return nil, err
		}
		if by, ok := droppedByAll(fwd); ok && by.Pos > 0 {
			notes = append(notes, fmt.Sprintf("%s matches port %d, but DNAT already rewrote the packet to %s:%d; "+
				"match the published port through conntrack (iptables: -m conntrack --ctorigdstport %d, nft: ct original proto-dst %d)",
				stepRef(by), o.Packet.OrigDstPort, o.Packet.Dst, o.Packet.DstPort, o.Packet.OrigDstPort, o.Packet.OrigDstPort))
		}
	}
	return notes, nil
}

func droppedByAll(outs []sim.Outcome) (sim.Step, bool) {
	if len(outs) == 0 {
		return sim.Step{}, false
	}
	for _, o := range outs {
		if !o.Decided || o.Verdict == ruleset.Accept || o.By == nil {
			return sim.Step{}, false
		}
	}
	return *outs[0].By, true
}

func stepRef(s sim.Step) string {
	if s.Pos == 0 {
		return fmt.Sprintf("the %s policy of %s %s", s.Text, s.Table, s.Chain)
	}
	return fmt.Sprintf("%s %s #%d %q", s.Table, s.Chain, s.Pos, s.Text)
}

type candidate struct {
	hint  Hint
	patch *ruleset.Ruleset
}

func (a *analyzer) hints(ctx context.Context, ex *Example) ([]Hint, error) {
	o := ex.Outcome
	if o.DNAT == nil || !o.Routed {
		return nil, nil
	}
	var cands []candidate
	if o.DNAT.Source.IsIPTables() {
		if c, ok := a.dockerUserHint(ex); ok {
			cands = append(cands, c)
		}
	}
	if o.DNAT.Source == ruleset.SourceNftables {
		cands = append(cands, a.nftGuardHint(ex))
	}
	var hints []Hint
	for _, c := range cands {
		ok, err := blocks(ctx, c.patch, a.pipe.Host(), ex.Sent)
		if err != nil {
			return nil, err
		}
		if ok {
			hints = append(hints, c.hint)
		}
	}
	if h, ok := a.loopbackHint(ex); ok {
		hints = append(hints, h)
	}
	return hints, nil
}

// blocks replays pkt against a patched ruleset and reports whether no
// branch delivers it any more.
func blocks(ctx context.Context, rs *ruleset.Ruleset, host *netpkt.Host, pkt netpkt.Packet) (bool, error) {
	outs, err := sim.New(rs, host).Simulate(ctx, pkt)
	if err != nil {
		return false, err
	}
	for _, o := range outs {
		if !o.Decided || o.Delivered() {
			return false, nil
		}
	}
	return len(outs) > 0, nil
}

// DockerUserRule is the rule the iptables hint inserts, without the
// "iptables -I DOCKER-USER" prefix.
func DockerUserRule(iface string, proto netpkt.Proto, port uint16) string {
	return fmt.Sprintf("-i %s -p %s -m conntrack --ctorigdstport %d -j DROP", iface, proto, port)
}

func (a *analyzer) dockerUserHint(ex *Example) (candidate, bool) {
	fam := ruleset.FamilyIP
	cmd := "iptables"
	if ex.Sent.Family == netpkt.IPv6 {
		fam, cmd = ruleset.FamilyIP6, "ip6tables"
	}
	for _, t := range a.snap.Ruleset.Tables {
		if t.Family != fam || t.Name != "filter" || !t.Source.IsIPTables() || t.Chain("DOCKER-USER") == nil {
			continue
		}
		spec := DockerUserRule(ex.Sent.InIface, ex.Sent.Proto, ex.Sent.DstPort)
		r, err := iptables.ParseRule(spec, ex.Sent.Family)
		if err != nil {
			return candidate{}, false
		}
		return candidate{Hint{Text: cmd + " -I DOCKER-USER " + spec, Doc: docDockerUser}, withRuleFirst(a.snap.Ruleset, t, "DOCKER-USER", r)}, true
	}
	return candidate{}, false
}

// NftGuardTable is the table the nftables hint suggests, in nft syntax.
func NftGuardTable(iface string, proto netpkt.Proto, port uint16) string {
	return fmt.Sprintf("table inet fwreach-guard {\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n"+
		"\t\tiifname %q meta l4proto %s ct original proto-dst %d drop\n\t}\n}", iface, proto, port)
}

// GuardTable is NftGuardTable in IR form; tests check the two agree.
func GuardTable(iface string, proto netpkt.Proto, port uint16) *ruleset.Table {
	return &ruleset.Table{Family: ruleset.FamilyInet, Name: "fwreach-guard", Source: ruleset.SourceNftables,
		Chains: []*ruleset.Chain{{
			Name: "forward",
			Base: &ruleset.BaseChain{Hook: netpkt.Forward, Kind: ruleset.KindFilter, Priority: 0, Policy: ruleset.Accept},
			Rules: []ruleset.Rule{{
				Pos:  1,
				Text: fmt.Sprintf("iifname %q meta l4proto %s ct original proto-dst %d drop", iface, proto, port),
				Matches: []ruleset.Match{
					ruleset.IfaceMatch{Name: iface},
					ruleset.ProtoMatch{Protos: []netpkt.Proto{proto}},
					ruleset.PortMatch{Dir: ruleset.DirDst, OrigDst: true, Ranges: []ruleset.PortRange{{From: port, To: port}}},
				},
				Action: ruleset.Action{Kind: ruleset.ActVerdict, Verdict: ruleset.Drop},
			}},
		}}}
}

func (a *analyzer) nftGuardHint(ex *Example) candidate {
	p := ex.Sent
	rs := &ruleset.Ruleset{Tables: append(append([]*ruleset.Table(nil), a.snap.Ruleset.Tables...), GuardTable(p.InIface, p.Proto, p.DstPort))}
	return candidate{Hint{Text: NftGuardTable(p.InIface, p.Proto, p.DstPort), Doc: docNftables}, rs}
}

// loopbackHint suggests publishing on 127.0.0.1. It cannot be replayed
// here because Docker generates the rules; the tests replay it against
// the iptables rules Docker generates for a loopback binding, so it is
// only offered for the iptables backend.
func (a *analyzer) loopbackHint(ex *Example) (Hint, bool) {
	c, ok := a.snap.ContainerByIP(ex.Outcome.Packet.Dst)
	if !ok || ex.Sent.Family != netpkt.IPv4 || !ex.Outcome.DNAT.Source.IsIPTables() {
		return Hint{}, false
	}
	for _, p := range c.Ports {
		if p.Proto == ex.Sent.Proto && p.HostPort == ex.Sent.DstPort && !p.HostIP.IsValid() {
			hp, cp := strconv.Itoa(int(p.HostPort)), strconv.Itoa(int(p.ContainerPort))
			return Hint{
				Text: "if only this host needs it, publish on loopback: -p 127.0.0.1:" + hp + ":" + cp +
					" (compose: \"127.0.0.1:" + hp + ":" + cp + "\")",
				Doc: docLoopback,
			}, true
		}
	}
	return Hint{}, false
}

func withRuleFirst(rs *ruleset.Ruleset, tbl *ruleset.Table, chain string, r ruleset.Rule) *ruleset.Ruleset {
	out := &ruleset.Ruleset{}
	for _, t := range rs.Tables {
		if t != tbl {
			out.Tables = append(out.Tables, t)
			continue
		}
		nt := *t
		nt.Chains = nil
		for _, c := range t.Chains {
			if c.Name == chain {
				nc := *c
				nc.Rules = append([]ruleset.Rule{r}, c.Rules...)
				c = &nc
			}
			nt.Chains = append(nt.Chains, c)
		}
		out.Tables = append(out.Tables, &nt)
	}
	return out
}
