// Package exposure decides, for every port worth asking about, which
// sources this host's netfilter lets reach a listener or a container.
package exposure

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"sync"

	"github.com/Santaniel0/fwreach/internal/expect"
	"github.com/Santaniel0/fwreach/internal/netpkt"
	"github.com/Santaniel0/fwreach/internal/ruleset"
	"github.com/Santaniel0/fwreach/internal/sim"
	"github.com/Santaniel0/fwreach/internal/snapshot"
	"github.com/Santaniel0/fwreach/internal/srcclass"
)

// ErrUnknownIface is returned when a requested interface is not in the snapshot.
var ErrUnknownIface = errors.New("interface not in snapshot")

// Status orders findings from harmless to bad.
type Status uint8

const (
	StatusFiltered Status = iota + 1
	StatusNoListener
	StatusPossible
	StatusExposed
)

func (s Status) String() string {
	switch s {
	case StatusFiltered:
		return "filtered"
	case StatusNoListener:
		return "no listener"
	case StatusPossible:
		return "possible"
	case StatusExposed:
		return "exposed"
	}
	return "status(" + strconv.Itoa(int(s)) + ")"
}

// Expectation is the verdict against the expectations file.
type Expectation uint8

const (
	ExpectNotChecked Expectation = iota
	ExpectOK
	ExpectViolation
)

func (e Expectation) String() string {
	switch e {
	case ExpectOK:
		return "expected"
	case ExpectViolation:
		return "unexpected"
	}
	return "not checked"
}

// Target is a port probed for one address family.
type Target struct {
	expect.ProtoPort
	Family netpkt.Family
}

// Reach is the set of sources allowed in through one interface.
type Reach struct {
	Iface  string
	Ranges []srcclass.Range
}

// Example is one simulated packet that shows the finding.
type Example struct {
	Sent    netpkt.Packet
	Outcome sim.Outcome
}

// Hint is a suggested fix together with the document it follows.
type Hint struct {
	Text string
	Doc  string
}

// Finding is the result for one target.
type Finding struct {
	Target
	Listeners []snapshot.Listener
	Status    Status
	Path      netpkt.Hook
	Sink      string
	Allowed   []Reach
	Possible  []Reach
	Expect    Expectation
	Example   *Example
	DependsOn []sim.Step
	Notes     []string
	Hints     []Hint
}

// Options tune Analyze.
type Options struct {
	Ifaces         []string
	Expect         *expect.Set
	FailOnPossible bool
	Workers        int
}

// Report is the outcome of Analyze.
type Report struct {
	Snapshot     *snapshot.Snapshot
	Ifaces       []netpkt.Iface
	Findings     []Finding
	UnknownRules []string
}

// Violations counts findings that break the expectations.
func (r *Report) Violations() int {
	n := 0
	for _, f := range r.Findings {
		if f.Expect == ExpectViolation {
			n++
		}
	}
	return n
}

type job struct {
	target int
	iface  string
	class  srcclass.Class
	pkt    netpkt.Packet
}

type analyzer struct {
	snap *snapshot.Snapshot
	pipe *sim.Pipeline
	opts Options
}

// Analyze simulates every target from every source class on every external
// interface and turns the outcomes into findings.
func Analyze(ctx context.Context, snap *snapshot.Snapshot, opts Options) (*Report, error) {
	a := &analyzer{snap: snap, pipe: sim.New(snap.Ruleset, snap.Host), opts: opts}
	ifaces, err := a.ifaces()
	if err != nil {
		return nil, err
	}
	rep := &Report{Snapshot: snap, Ifaces: ifaces, UnknownRules: unknownRules(snap.Ruleset)}
	targets := a.targets(ifaces)
	classes := map[netpkt.Family][]srcclass.Class{}
	var jobs []job
	for ti, t := range targets {
		cls, ok := classes[t.Family]
		if !ok {
			cls = srcclass.Partition(t.Family, a.prefixes(t.Family))
			classes[t.Family] = cls
		}
		for _, ifc := range ifaces {
			dst, ok := addrOf(ifc, t.Family)
			if !ok {
				continue
			}
			for _, c := range cls {
				jobs = append(jobs, job{target: ti, iface: ifc.Name, class: c,
					pkt: netpkt.NewInbound(t.Proto, c.Rep, dst, t.Port, ifc.Name)})
			}
		}
	}
	results, err := a.run(ctx, jobs)
	if err != nil {
		return nil, err
	}
	for ti, t := range targets {
		f, err := a.finding(ctx, t, jobs, results, ti)
		if err != nil {
			return nil, err
		}
		rep.Findings = append(rep.Findings, f)
	}
	return rep, nil
}

func (a *analyzer) ifaces() ([]netpkt.Iface, error) {
	names := a.opts.Ifaces
	if len(names) == 0 {
		names = a.snap.ExternalIfaces()
	}
	var out []netpkt.Iface
	for _, n := range names {
		ifc, ok := a.snap.Iface(n)
		if !ok {
			return nil, fmt.Errorf("%q: %w", n, ErrUnknownIface)
		}
		out = append(out, ifc)
	}
	return out, nil
}

func addrOf(ifc netpkt.Iface, fam netpkt.Family) (netip.Addr, bool) {
	for _, a := range snapshot.GlobalAddrs(ifc) {
		if netpkt.FamilyOf(a) == fam {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// targets collects the ports worth probing: listeners not bound to
// loopback, Docker published ports and DNAT rules. Anything else has
// nothing behind it that a packet could reach.
func (a *analyzer) targets(ifaces []netpkt.Iface) []Target {
	seen := map[Target]bool{}
	add := func(pp expect.ProtoPort, fams ...netpkt.Family) {
		for _, f := range fams {
			seen[Target{ProtoPort: pp, Family: f}] = true
		}
	}
	both := []netpkt.Family{netpkt.IPv4, netpkt.IPv6}
	for _, l := range a.snap.Listeners {
		pp := expect.ProtoPort{Proto: l.Proto, Port: l.Port}
		switch {
		case l.Wildcard || l.Addr == netip.IPv6Unspecified():
			add(pp, both...)
		case !l.Addr.IsLoopback():
			add(pp, netpkt.FamilyOf(l.Addr))
		}
	}
	for _, c := range a.snap.Containers {
		for _, p := range c.Ports {
			pp := expect.ProtoPort{Proto: p.Proto, Port: p.HostPort}
			if p.HostIP.IsValid() {
				add(pp, netpkt.FamilyOf(p.HostIP))
			} else {
				add(pp, both...)
			}
		}
	}
	for _, pp := range dnatPorts(a.snap.Ruleset) {
		add(pp.ProtoPort, pp.Family)
	}
	var out []Target
	for t := range seen {
		if !slices.Contains(a.snap.Families, t.Family) {
			continue
		}
		for _, ifc := range ifaces {
			if _, ok := addrOf(ifc, t.Family); ok {
				out = append(out, t)
				break
			}
		}
	}
	slices.SortFunc(out, func(x, y Target) int {
		return cmp.Or(cmp.Compare(x.Proto, y.Proto), cmp.Compare(x.Port, y.Port), cmp.Compare(x.Family, y.Family))
	})
	return out
}

// dnatPorts finds destination ports of DNAT and REDIRECT rules, so a port
// forward to a host fwreach knows nothing else about is still probed.
func dnatPorts(rs *ruleset.Ruleset) []Target {
	var out []Target
	for _, t := range rs.Tables {
		for _, c := range t.Chains {
			for _, r := range c.Rules {
				if r.Action.Kind != ruleset.ActDNAT && r.Action.Kind != ruleset.ActRedirect {
					continue
				}
				protos := []netpkt.Proto{netpkt.ProtoTCP, netpkt.ProtoUDP}
				var ports []ruleset.PortRange
				for _, m := range r.Matches {
					switch m := m.(type) {
					case ruleset.ProtoMatch:
						if !m.Negate {
							protos = m.Protos
						}
					case ruleset.PortMatch:
						if m.Dir == ruleset.DirDst && !m.Negate && !m.OrigDst {
							ports = m.Ranges
						}
					}
				}
				for _, pr := range ports {
					if pr.To-pr.From > 16 {
						continue
					}
					for p := int(pr.From); p <= int(pr.To); p++ {
						for _, proto := range protos {
							for _, fam := range []netpkt.Family{netpkt.IPv4, netpkt.IPv6} {
								if t.Family.Covers(fam) {
									out = append(out, Target{ProtoPort: expect.ProtoPort{Proto: proto, Port: uint16(p)}, Family: fam})
								}
							}
						}
					}
				}
			}
		}
	}
	return out
}

// prefixes returns every source prefix that can change a verdict: those in
// rules and those in the expectations file.
func (a *analyzer) prefixes(fam netpkt.Family) []netip.Prefix {
	var out []netip.Prefix
	for _, t := range a.snap.Ruleset.Tables {
		for _, c := range t.Chains {
			for _, r := range c.Rules {
				for _, m := range r.Matches {
					if am, ok := m.(ruleset.AddrMatch); ok && am.Dir == ruleset.DirSrc && am.Family == fam {
						out = append(out, am.Prefixes...)
					}
				}
			}
		}
	}
	if a.opts.Expect != nil {
		out = append(out, a.opts.Expect.Prefixes()...)
	}
	return out
}

// run simulates all jobs on a bounded pool. Results are stored by job
// index, so the output order does not depend on scheduling.
func (a *analyzer) run(ctx context.Context, jobs []job) ([][]sim.Outcome, error) {
	workers := a.opts.Workers
	if workers < 1 {
		workers = runtime.GOMAXPROCS(0)
	}
	workers = min(workers, len(jobs))
	results := make([][]sim.Outcome, len(jobs))
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	next := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for i := range next {
				outs, err := a.pipe.Simulate(ctx, jobs[i].pkt)
				if err != nil {
					cancel(err)
					continue
				}
				results[i] = outs
			}
		})
	}
feed:
	for i := range jobs {
		select {
		case next <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(next)
	wg.Wait()
	if err := context.Cause(ctx); err != nil {
		return nil, fmt.Errorf("simulate: %w", err)
	}
	return results, nil
}

type classResult uint8

const (
	crBlocked classResult = iota + 1
	crNoSink
	crPossible
	crAllowed
)

// sink names what receives a delivered packet: a listening socket for
// local delivery, a container (or bare address) for forwarded traffic.
func (a *analyzer) sink(o sim.Outcome, iface string) (string, bool) {
	if !o.Delivered() {
		return "", false
	}
	p := o.Packet
	if o.Local {
		for _, l := range a.snap.Listeners {
			if l.Proto == p.Proto && l.Port == p.DstPort && l.Accepts(p.Dst, iface) {
				return l.String(), true
			}
		}
		return "", false
	}
	dst := netip.AddrPortFrom(p.Dst, p.DstPort).String()
	if c, ok := a.snap.ContainerByIP(p.Dst); ok {
		return "container " + c.Name + " " + dst, true
	}
	return dst + " via " + p.OutIface, true
}

func (a *analyzer) classify(outs []sim.Outcome, iface string) classResult {
	reach, undecided, accepted := 0, false, false
	for _, o := range outs {
		if _, ok := a.sink(o, iface); ok {
			reach++
		}
		undecided = undecided || !o.Decided
		accepted = accepted || o.Delivered()
	}
	switch {
	case len(outs) > 0 && reach == len(outs):
		return crAllowed
	case reach > 0 || undecided:
		return crPossible
	case accepted:
		return crNoSink
	}
	return crBlocked
}

func (a *analyzer) finding(ctx context.Context, t Target, jobs []job, results [][]sim.Outcome, ti int) (Finding, error) {
	f := Finding{Target: t, Status: StatusFiltered}
	for _, l := range a.snap.Listeners {
		if l.Proto == t.Proto && l.Port == t.Port && (l.Wildcard || l.Addr.IsUnspecified() || netpkt.FamilyOf(l.Addr) == t.Family) {
			f.Listeners = append(f.Listeners, l)
		}
	}
	allowed, possible := map[string][]srcclass.Range{}, map[string][]srcclass.Range{}
	var first, best *Example
	violation := false
	for ji, j := range jobs {
		if j.target != ti {
			continue
		}
		outs := results[ji]
		if first == nil && len(outs) > 0 {
			first = &Example{Sent: j.pkt, Outcome: outs[0]}
		}
		cr := a.classify(outs, j.iface)
		switch cr {
		case crAllowed:
			allowed[j.iface] = append(allowed[j.iface], j.class.Range)
			f.Status = max(f.Status, StatusExposed)
		case crPossible:
			possible[j.iface] = append(possible[j.iface], j.class.Range)
			f.Status = max(f.Status, StatusPossible)
			f.DependsOn = appendAssumed(f.DependsOn, outs)
		case crNoSink:
			f.Status = max(f.Status, StatusNoListener)
		}
		if cr == crAllowed || cr == crPossible {
			for _, o := range outs {
				if _, ok := a.sink(o, j.iface); ok && (best == nil || j.class.Rep == srcclass.Sample(t.Family)) {
					best = &Example{Sent: j.pkt, Outcome: o}
					break
				}
			}
			if a.opts.Expect != nil && (cr == crAllowed || a.opts.FailOnPossible) && !a.opts.Expect.Allows(t.ProtoPort, j.class.Rep) {
				violation = true
			}
		}
	}
	f.Allowed, f.Possible = reaches(allowed), reaches(possible)
	f.Example = cmp.Or(best, first)
	if a.opts.Expect != nil {
		f.Expect = ExpectOK
		if violation {
			f.Expect = ExpectViolation
		}
	}
	if best == nil {
		return f, nil
	}
	o := best.Outcome
	f.Sink, _ = a.sink(o, best.Sent.InIface)
	f.Path = netpkt.Input
	if o.Routed {
		f.Path = netpkt.Forward
		var err error
		if f.Notes, err = a.notes(ctx, best); err != nil {
			return f, err
		}
		if f.Hints, err = a.hints(ctx, best); err != nil {
			return f, err
		}
	}
	return f, nil
}

func appendAssumed(dst []sim.Step, outs []sim.Outcome) []sim.Step {
	for _, o := range outs {
		for _, as := range o.Assumed {
			if !slices.ContainsFunc(dst, func(s sim.Step) bool {
				return s.Table == as.Step.Table && s.Chain == as.Step.Chain && s.Pos == as.Step.Pos
			}) {
				dst = append(dst, as.Step)
			}
		}
		if !o.Decided && len(o.Trace) > 0 {
			last := o.Trace[len(o.Trace)-1]
			if last.Note != "" && !slices.Contains(dst, last) {
				dst = append(dst, last)
			}
		}
	}
	return dst
}

func reaches(m map[string][]srcclass.Range) []Reach {
	var out []Reach
	for ifc, rs := range m {
		out = append(out, Reach{Iface: ifc, Ranges: srcclass.Merge(rs)})
	}
	slices.SortFunc(out, func(x, y Reach) int { return cmp.Compare(x.Iface, y.Iface) })
	return out
}

func unknownRules(rs *ruleset.Ruleset) []string {
	var out []string
	for _, t := range rs.Tables {
		for _, c := range t.Chains {
			for _, r := range c.Rules {
				if r.HasUnknown() {
					out = append(out, fmt.Sprintf("%s %s #%d  %s", t.ID(), c.Name, r.Pos, r.Text))
				}
			}
		}
	}
	return out
}

// Explained is one outcome of `fwreach explain`.
type Explained struct {
	Outcome sim.Outcome
	Sink    string
	Notes   []string
	Hints   []Hint
}

// Explain simulates a single packet and annotates every outcome.
func Explain(ctx context.Context, snap *snapshot.Snapshot, pkt netpkt.Packet) ([]Explained, error) {
	a := &analyzer{snap: snap, pipe: sim.New(snap.Ruleset, snap.Host)}
	outs, err := a.pipe.Simulate(ctx, pkt)
	if err != nil {
		return nil, err
	}
	var res []Explained
	for _, o := range outs {
		e := Explained{Outcome: o}
		e.Sink, _ = a.sink(o, pkt.InIface)
		if o.Routed && e.Sink != "" {
			ex := &Example{Sent: pkt, Outcome: o}
			if e.Notes, err = a.notes(ctx, ex); err != nil {
				return nil, err
			}
			if e.Hints, err = a.hints(ctx, ex); err != nil {
				return nil, err
			}
		}
		res = append(res, e)
	}
	return res, nil
}
