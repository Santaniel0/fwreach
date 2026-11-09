// Package report renders an exposure report as text or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Santaniel0/fwreach/internal/exposure"
	"github.com/Santaniel0/fwreach/internal/netpkt"
	"github.com/Santaniel0/fwreach/internal/sim"
	"github.com/Santaniel0/fwreach/internal/srcclass"
)

// Text writes the human report. verbose adds traces for every finding and
// lists the rules fwreach could not model.
func Text(w io.Writer, rep *exposure.Report, verbose bool) error {
	ew := &errWriter{w: w}
	snap := rep.Snapshot
	ew.printf("fwreach: what this host's netfilter allows inbound (simulated from a snapshot, no packets sent)\n")
	if snap.Manifest.Host != "" {
		ew.printf("host        %s, collected %s\n", snap.Manifest.Host, snap.Manifest.CollectedAt.UTC().Format(time.RFC3339))
	}
	total := 0
	for i, s := range snap.Sources {
		label := "rules      "
		if i > 0 {
			label = "           "
		}
		ew.printf("%s %s: %s, %d tables, %d rules\n", label, s.File, s.Source, s.Tables, s.Rules)
		total += s.Rules
	}
	var ifs []string
	for _, ifc := range rep.Ifaces {
		var addrs []string
		for _, a := range globalAddrs(ifc) {
			addrs = append(addrs, a.String())
		}
		ifs = append(ifs, ifc.Name+" "+strings.Join(addrs, " "))
	}
	ew.printf("interfaces  %s\n", strings.Join(ifs, "; "))
	possible := 0
	for _, f := range rep.Findings {
		if f.Status == exposure.StatusPossible {
			possible++
		}
	}
	ew.printf("coverage    %d of %d rules use matches or targets fwreach does not model; %d findings depend on them\n",
		len(rep.UnknownRules), total, possible)
	for _, warn := range snap.Warnings {
		ew.printf("warning     %s\n", warn)
	}
	ew.printf("\n")

	tw := tabwriter.NewWriter(ew, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PORT\tFAMILY\tSTATUS\tALLOWED FROM\tDELIVERED TO")
	for _, f := range rep.Findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", f.ProtoPort, f.Family, status(f), reachText(f), deliveredText(f))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	for _, f := range rep.Findings {
		if verbose || shouldDetail(f) {
			detail(ew, f)
		}
	}
	if verbose && len(rep.UnknownRules) > 0 {
		ew.printf("\nrules with matches or targets fwreach does not model:\n")
		for _, r := range rep.UnknownRules {
			ew.printf("  %s\n", r)
		}
	}
	if n := rep.Violations(); n > 0 {
		ew.printf("\n%d unexpected exposure(s)\n", n)
	} else if anyChecked(rep) {
		ew.printf("\nno unexpected exposures\n")
	}
	return ew.err
}

func anyChecked(rep *exposure.Report) bool {
	for _, f := range rep.Findings {
		if f.Expect != exposure.ExpectNotChecked {
			return true
		}
	}
	return false
}

func shouldDetail(f exposure.Finding) bool {
	if f.Expect == exposure.ExpectViolation || f.Status == exposure.StatusPossible {
		return true
	}
	return f.Expect == exposure.ExpectNotChecked && f.Status == exposure.StatusExposed && f.Path == netpkt.Forward
}

func status(f exposure.Finding) string {
	s := f.Status.String()
	switch f.Expect {
	case exposure.ExpectViolation:
		return strings.ToUpper(s) + ", UNEXPECTED"
	case exposure.ExpectOK:
		if f.Status >= exposure.StatusPossible {
			return s + ", expected"
		}
	}
	return s
}

func reachText(f exposure.Finding) string {
	var parts []string
	for _, r := range f.Allowed {
		parts = append(parts, rangesText(f.Family, r.Ranges)+" via "+r.Iface)
	}
	for _, r := range f.Possible {
		parts = append(parts, "maybe "+rangesText(f.Family, r.Ranges)+" via "+r.Iface)
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, "; ")
}

// rangesText prints "any", a short CIDR list, or "any except ..." when the
// complement is the shorter way to say it.
func rangesText(fam netpkt.Family, rs []srcclass.Range) string {
	if srcclass.IsAll(fam, rs) {
		return "any"
	}
	in := cidrs(rs)
	all := srcclass.Partition(fam, nil)[0].Range
	var gaps []srcclass.Range
	cur := all.From
	for _, r := range rs {
		if r.From.Compare(cur) > 0 {
			gaps = append(gaps, srcclass.Range{From: cur, To: r.From.Prev()})
		}
		cur = r.To.Next()
		if !cur.IsValid() {
			break
		}
	}
	if cur.IsValid() {
		gaps = append(gaps, srcclass.Range{From: cur, To: all.To})
	}
	if out := cidrs(gaps); len(out) < len(in) {
		return "any except " + strings.Join(out, ",")
	}
	return strings.Join(in, ",")
}

func cidrs(rs []srcclass.Range) []string {
	var out []string
	for _, r := range rs {
		for _, p := range srcclass.Prefixes(r) {
			out = append(out, p.String())
		}
	}
	return out
}

func deliveredText(f exposure.Finding) string {
	if f.Sink != "" {
		return f.Sink
	}
	var ls []string
	for _, l := range f.Listeners {
		ls = append(ls, l.String())
	}
	if len(ls) == 0 {
		return "-"
	}
	return "(listening: " + strings.Join(ls, ", ") + ")"
}

func detail(ew *errWriter, f exposure.Finding) {
	if f.Example == nil {
		return
	}
	ex := f.Example
	o := ex.Outcome
	ew.printf("\n%s %s from %s on %s: ", f.ProtoPort, f.Family, ex.Sent.Src, ex.Sent.InIface)
	switch {
	case f.Sink != "":
		ew.printf("delivered to %s\n", f.Sink)
	case !o.Decided:
		ew.printf("undecided\n")
	default:
		ew.printf("%s\n", f.Status)
	}
	TraceLines(ew, o.Trace)
	if o.Decided && o.Delivered() && f.Sink == "" {
		ew.printf("  %-11s nothing listens on %s:%d\n", "result", o.Packet.Dst, o.Packet.DstPort)
	}
	for _, s := range f.DependsOn {
		ew.printf("  %-11s %s\n", "depends on", s.Describe())
	}
	for _, n := range f.Notes {
		ew.printf("  %-11s %s\n", "note", n)
	}
	if f.Expect == exposure.ExpectOK {
		return
	}
	for _, h := range f.Hints {
		lines := strings.Split(h.Text, "\n")
		ew.printf("  %-11s %s\n", "fix", lines[0])
		for _, l := range lines[1:] {
			ew.printf("  %-11s %s\n", "", l)
		}
		ew.printf("  %-11s see %s\n", "", h.Doc)
	}
}

// TraceLines prints a trace with the hook in the first column.
func TraceLines(w io.Writer, trace []sim.Step) {
	for _, s := range trace {
		hook := "routing"
		if s.Table != "" {
			hook = s.Hook.String()
		}
		fmt.Fprintf(w, "  %-11s %s\n", hook, s.Describe())
	}
}

func globalAddrs(ifc netpkt.Iface) []netip.Addr {
	var out []netip.Addr
	for _, p := range ifc.Addrs {
		if a := p.Addr(); !a.IsLoopback() && !a.IsLinkLocalUnicast() {
			out = append(out, a)
		}
	}
	return out
}

type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.w.Write(p)
	e.err = err
	return n, err
}

func (e *errWriter) printf(format string, args ...any) {
	fmt.Fprintf(e, format, args...)
}

type jsonReport struct {
	Host         string        `json:"host,omitempty"`
	Interfaces   []string      `json:"interfaces"`
	UnknownRules []string      `json:"unknown_rules"`
	Warnings     []string      `json:"warnings"`
	Violations   int           `json:"violations"`
	Findings     []jsonFinding `json:"findings"`
}

type jsonFinding struct {
	Port        string     `json:"port"`
	Family      string     `json:"family"`
	Status      string     `json:"status"`
	Expectation string     `json:"expectation"`
	Path        string     `json:"path,omitempty"`
	DeliveredTo string     `json:"delivered_to,omitempty"`
	Allowed     []jsonFrom `json:"allowed_from"`
	Possible    []jsonFrom `json:"possibly_from"`
	Trace       []string   `json:"trace,omitempty"`
	DependsOn   []string   `json:"depends_on,omitempty"`
	Notes       []string   `json:"notes,omitempty"`
	Hints       []Hint     `json:"hints,omitempty"`
}

type jsonFrom struct {
	Iface    string   `json:"iface"`
	Prefixes []string `json:"prefixes"`
}

// Hint is the JSON form of exposure.Hint.
type Hint struct {
	Text string `json:"text"`
	Doc  string `json:"doc"`
}

// JSON writes the report as one JSON document.
func JSON(w io.Writer, rep *exposure.Report) error {
	out := jsonReport{Host: rep.Snapshot.Manifest.Host, UnknownRules: nonNil(rep.UnknownRules),
		Warnings: nonNil(rep.Snapshot.Warnings), Violations: rep.Violations(), Findings: []jsonFinding{}}
	for _, ifc := range rep.Ifaces {
		out.Interfaces = append(out.Interfaces, ifc.Name)
	}
	for _, f := range rep.Findings {
		jf := jsonFinding{Port: f.ProtoPort.String(), Family: f.Family.String(), Status: f.Status.String(),
			Expectation: f.Expect.String(), DeliveredTo: f.Sink,
			Allowed: froms(f.Allowed), Possible: froms(f.Possible), Notes: f.Notes}
		if f.Path != 0 {
			jf.Path = f.Path.String()
		}
		if f.Example != nil {
			for _, s := range f.Example.Outcome.Trace {
				jf.Trace = append(jf.Trace, s.Describe())
			}
		}
		for _, s := range f.DependsOn {
			jf.DependsOn = append(jf.DependsOn, s.Describe())
		}
		for _, h := range f.Hints {
			jf.Hints = append(jf.Hints, Hint(h))
		}
		out.Findings = append(out.Findings, jf)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func froms(rs []exposure.Reach) []jsonFrom {
	out := []jsonFrom{}
	for _, r := range rs {
		jf := jsonFrom{Iface: r.Iface}
		for _, rg := range r.Ranges {
			for _, p := range srcclass.Prefixes(rg) {
				jf.Prefixes = append(jf.Prefixes, p.String())
			}
		}
		out = append(out, jf)
	}
	return out
}

func nonNil(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}
