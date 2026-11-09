// Package sim walks a packet through the netfilter hooks of a ruleset.
//
// The semantics it implements, because they are what people get wrong:
//   - every base chain registered on a hook runs, in priority order, whether
//     it came from legacy iptables, iptables-nft or native nftables;
//   - accept only ends the current base chain, drop and reject are final;
//   - of the NAT chains on a hook, the first one that translates wins and
//     later NAT chains on that hook are skipped;
//   - after prerouting the packet goes to input if its (possibly rewritten)
//     destination is local, otherwise to forward.
package sim

import (
	"cmp"
	"context"
	"slices"
	"strconv"
	"strings"

	"github.com/Santaniel0/fwreach/internal/netpkt"
	"github.com/Santaniel0/fwreach/internal/ruleset"
)

const (
	maxDepth = 64
	// maxForks bounds the work done for one packet when rules contain
	// matches fwreach cannot decide. Past it the result is undecided.
	maxForks = 256
)

// Step is one entry of a packet trace.
type Step struct {
	Hook   netpkt.Hook
	Source ruleset.Source
	Table  string
	Chain  string
	Pos    int // 0 means the chain policy or a pseudo step
	Text   string
	Note   string
}

// Assumption records how an undecidable rule was treated in one branch.
type Assumption struct {
	Step    Step
	Matched bool
}

// Outcome is one possible fate of the packet. There is more than one when
// rules with unknown matches forked the evaluation.
type Outcome struct {
	Decided bool
	Verdict ruleset.Verdict
	Packet  netpkt.Packet
	Local   bool
	Routed  bool
	Trace   []Step
	Assumed []Assumption
	By      *Step
	DNAT    *Step
}

// Delivered reports whether the packet was accepted and has somewhere to go.
func (o Outcome) Delivered() bool {
	return o.Decided && o.Verdict == ruleset.Accept && (o.Local || o.Routed)
}

type baseRef struct {
	table *ruleset.Table
	chain *ruleset.Chain
}

// Pipeline is an immutable view of a ruleset ordered per hook. It is safe
// for concurrent use.
type Pipeline struct {
	host  *netpkt.Host
	hooks map[netpkt.Hook][]baseRef
}

// New orders the base chains of rs by hook and priority. Ties keep table
// order, which matches nothing the kernel promises, so tests avoid them.
func New(rs *ruleset.Ruleset, host *netpkt.Host) *Pipeline {
	p := &Pipeline{host: host, hooks: make(map[netpkt.Hook][]baseRef)}
	for _, t := range rs.Tables {
		for _, c := range t.Chains {
			if c.Base != nil {
				p.hooks[c.Base.Hook] = append(p.hooks[c.Base.Hook], baseRef{t, c})
			}
		}
	}
	for h := range p.hooks {
		slices.SortStableFunc(p.hooks[h], func(a, b baseRef) int {
			return cmp.Compare(a.chain.Base.Priority, b.chain.Base.Priority)
		})
	}
	return p
}

// Host returns the host model the pipeline evaluates against.
func (p *Pipeline) Host() *netpkt.Host { return p.host }

type branch struct {
	pkt     netpkt.Packet
	trace   []Step
	assumed []Assumption
	natDone bool
	dnat    *Step
}

func (b branch) fork() branch {
	b.trace = slices.Clone(b.trace)
	b.assumed = slices.Clone(b.assumed)
	return b
}

type exitKind uint8

const (
	exitFall exitKind = iota + 1
	exitVerdict
	exitTruncated
)

type chainExit struct {
	b       branch
	kind    exitKind
	verdict ruleset.Verdict
	by      Step
}

type evaluator struct {
	p     *Pipeline
	forks int
}

// Simulate runs pkt through prerouting, the routing decision and then
// input or forward.
func (p *Pipeline) Simulate(ctx context.Context, pkt netpkt.Packet) ([]Outcome, error) {
	e := &evaluator{p: p}
	live, done, err := e.runHook(ctx, netpkt.Prerouting, []branch{{pkt: pkt}})
	if err != nil {
		return nil, err
	}
	var input, forward []branch
	for _, b := range live {
		if p.host.IsLocal(b.pkt.Dst) {
			b.trace = append(b.trace, Step{Note: b.pkt.Dst.String() + " is a local address: input"})
			input = append(input, b)
			continue
		}
		ifc, ok := p.host.Route(b.pkt.Dst)
		if !ok {
			b.trace = append(b.trace, Step{Note: "no connected route to " + b.pkt.Dst.String()})
			done = append(done, outcome(b, true, ruleset.Accept, nil, false, false))
			continue
		}
		b.pkt.OutIface = ifc
		b.trace = append(b.trace, Step{Note: b.pkt.Dst.String() + " is on " + ifc + ": forward"})
		forward = append(forward, b)
	}
	for _, leg := range []struct {
		hook  netpkt.Hook
		bs    []branch
		local bool
	}{{netpkt.Input, input, true}, {netpkt.Forward, forward, false}} {
		live, out, err := e.runHook(ctx, leg.hook, leg.bs)
		if err != nil {
			return nil, err
		}
		done = append(done, out...)
		for _, b := range live {
			done = append(done, outcome(b, true, ruleset.Accept, nil, leg.local, !leg.local))
		}
	}
	return done, nil
}

// RunHook evaluates a single hook for pkt. It answers questions such as
// "what would input have done with this packet had DNAT not moved it".
func (p *Pipeline) RunHook(ctx context.Context, hook netpkt.Hook, pkt netpkt.Packet) ([]Outcome, error) {
	e := &evaluator{p: p}
	live, done, err := e.runHook(ctx, hook, []branch{{pkt: pkt}})
	if err != nil {
		return nil, err
	}
	for _, b := range live {
		done = append(done, outcome(b, true, ruleset.Accept, nil, false, false))
	}
	return done, nil
}

func outcome(b branch, decided bool, v ruleset.Verdict, by *Step, local, routed bool) Outcome {
	return Outcome{Decided: decided, Verdict: v, Packet: b.pkt, Local: local, Routed: routed,
		Trace: b.trace, Assumed: b.assumed, By: by, DNAT: b.dnat}
}

func (e *evaluator) runHook(ctx context.Context, hook netpkt.Hook, bs []branch) ([]branch, []Outcome, error) {
	var done []Outcome
	for i := range bs {
		bs[i].natDone = false
	}
	for _, ref := range e.p.hooks[hook] {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		var next []branch
		for _, b := range bs {
			if !ref.table.Family.Covers(b.pkt.Family) || (ref.chain.Base.Kind == ruleset.KindNAT && b.natDone) {
				next = append(next, b)
				continue
			}
			for _, ex := range e.runChain(b, ref.table, ref.chain, 0, 0) {
				switch ex.kind {
				case exitTruncated:
					done = append(done, outcome(ex.b, false, 0, nil, false, false))
				case exitVerdict:
					if ex.verdict == ruleset.Accept {
						next = append(next, ex.b)
						continue
					}
					by := ex.by
					done = append(done, outcome(ex.b, true, ex.verdict, &by, false, false))
				case exitFall:
					pol := ref.chain.Base.Policy
					st := Step{Hook: hook, Source: ref.table.Source, Table: ref.table.ID(), Chain: ref.chain.Name,
						Text: "policy " + pol.String()}
					ex.b.trace = append(ex.b.trace, st)
					if pol == ruleset.Accept {
						next = append(next, ex.b)
						continue
					}
					done = append(done, outcome(ex.b, true, pol, &st, false, false))
				}
			}
		}
		bs = next
	}
	return bs, done, nil
}

func (e *evaluator) runChain(b branch, t *ruleset.Table, c *ruleset.Chain, from, depth int) []chainExit {
	if depth > maxDepth {
		return []chainExit{{b: b, kind: exitTruncated}}
	}
	hook := netpkt.Hook(0)
	if c.Base != nil {
		hook = c.Base.Hook
	}
	var out []chainExit
	for i := from; i < len(c.Rules); i++ {
		r := c.Rules[i]
		if !r.Action.Terminal() {
			continue
		}
		st := Step{Hook: hook, Source: t.Source, Table: t.ID(), Chain: c.Name, Pos: r.Pos, Text: r.Text}
		switch ruleset.EvalAll(r.Matches, &b.pkt, e.p.host) {
		case netpkt.No:
			continue
		case netpkt.Unknown:
			if e.forks >= maxForks {
				return append(out, chainExit{b: b, kind: exitTruncated})
			}
			e.forks++
			skip := b.fork()
			skip.assumed = append(skip.assumed, Assumption{Step: st, Matched: false})
			out = append(out, e.runChain(skip, t, c, i+1, depth)...)
			b = b.fork()
			b.assumed = append(b.assumed, Assumption{Step: st, Matched: true})
			st.Note = "assumed to match"
		}
		a := r.Action
		switch a.Kind {
		case ruleset.ActVerdict:
			b.trace = append(b.trace, st)
			return append(out, chainExit{b: b, kind: exitVerdict, verdict: a.Verdict, by: st})
		case ruleset.ActReturn:
			b.trace = append(b.trace, st)
			return append(out, chainExit{b: b, kind: exitFall})
		case ruleset.ActJump, ruleset.ActGoto:
			target := t.Chain(a.Target)
			if target == nil {
				st.Note = "jump to missing chain"
				b.trace = append(b.trace, st)
				return append(out, chainExit{b: b, kind: exitTruncated})
			}
			b.trace = append(b.trace, st)
			for _, sub := range e.runChain(b, t, target, 0, depth+1) {
				if sub.kind != exitFall || a.Kind == ruleset.ActGoto {
					out = append(out, sub)
					continue
				}
				out = append(out, e.runChain(sub.b, t, c, i+1, depth)...)
			}
			return out
		case ruleset.ActDNAT, ruleset.ActRedirect:
			if a.DNATAddr.IsValid() {
				b.pkt.Dst = a.DNATAddr
			}
			if a.DNATPort != 0 {
				b.pkt.DstPort = a.DNATPort
			}
			b.pkt.DNATed = true
			b.natDone = true
			b.trace = append(b.trace, st)
			dn := st
			b.dnat = &dn
			return append(out, chainExit{b: b, kind: exitVerdict, verdict: ruleset.Accept, by: st})
		case ruleset.ActSetMark:
			b.pkt.Mark = b.pkt.Mark&^a.MarkMask | a.Mark
			b.trace = append(b.trace, st)
		default:
			st.Note = "action not modeled: " + a.What
			b.trace = append(b.trace, st)
			return append(out, chainExit{b: b, kind: exitTruncated})
		}
	}
	return append(out, chainExit{b: b, kind: exitFall})
}

// Describe renders a step on one line for reports.
func (s Step) Describe() string {
	var sb strings.Builder
	if s.Table == "" {
		sb.WriteString(s.Note)
		return sb.String()
	}
	if s.Source == ruleset.SourceIPTablesLegacy {
		sb.WriteString("legacy ")
	}
	sb.WriteString(s.Table + " " + s.Chain)
	if s.Pos > 0 {
		sb.WriteString(" #" + strconv.Itoa(s.Pos))
	}
	sb.WriteString("  " + s.Text)
	if s.Note != "" {
		sb.WriteString("  (" + s.Note + ")")
	}
	return sb.String()
}
