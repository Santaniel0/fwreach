// Command fwreach reports which ports a Linux host's netfilter rules let in,
// by simulating packets against a snapshot of the rules.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/Santaniel0/fwreach/internal/expect"
	"github.com/Santaniel0/fwreach/internal/exposure"
	"github.com/Santaniel0/fwreach/internal/netpkt"
	"github.com/Santaniel0/fwreach/internal/report"
	"github.com/Santaniel0/fwreach/internal/snapshot"
	"github.com/Santaniel0/fwreach/internal/srcclass"
)

const (
	exitOK        = 0
	exitViolation = 1
	exitError     = 2
)

const usage = `usage:
  fwreach analyze [-format text|json] [-expect FILE] [-iface NAME]... [-fail-on-possible] [-v] SNAPSHOT_DIR
  fwreach explain -port tcp/5432 [-from ADDR] [-iface NAME] [-to ADDR] SNAPSHOT_DIR

exit codes: 0 ok, 1 unexpected exposure (with -expect), 2 error
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitError
	}
	var err error
	code := exitOK
	switch args[0] {
	case "analyze":
		code, err = analyze(ctx, args[1:], stdout)
	case "explain":
		err = explain(ctx, args[1:], stdout)
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		err = fmt.Errorf("unknown command %q", args[0])
	}
	if err != nil {
		fmt.Fprintf(stderr, "fwreach: %v\n", err)
		if errors.Is(err, errUsage) {
			fmt.Fprint(stderr, usage)
		}
		return exitError
	}
	return code
}

var errUsage = errors.New("bad usage")

type ifaceList []string

func (l *ifaceList) String() string     { return strings.Join(*l, ",") }
func (l *ifaceList) Set(v string) error { *l = append(*l, v); return nil }

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parse(fs *flag.FlagSet, args []string) (string, error) {
	if err := fs.Parse(args); err != nil {
		return "", fmt.Errorf("%w: %w", errUsage, err)
	}
	if fs.NArg() != 1 {
		return "", fmt.Errorf("%w: want exactly one snapshot directory", errUsage)
	}
	return fs.Arg(0), nil
}

func analyze(ctx context.Context, args []string, stdout io.Writer) (int, error) {
	fs := newFlags("analyze")
	format := fs.String("format", "text", "text or json")
	expectFile := fs.String("expect", "", "expectations file")
	failPossible := fs.Bool("fail-on-possible", false, "count POSSIBLE findings against the expectations")
	verbose := fs.Bool("v", false, "show traces for every finding")
	workers := fs.Int("workers", 0, "simulation workers (default GOMAXPROCS)")
	var ifaces ifaceList
	fs.Var(&ifaces, "iface", "external interface to probe (repeatable; default: guessed)")
	dir, err := parse(fs, args)
	if err != nil {
		return exitError, err
	}
	if *format != "text" && *format != "json" {
		return exitError, fmt.Errorf("%w: -format must be text or json", errUsage)
	}
	snap, err := snapshot.Load(dir)
	if err != nil {
		return exitError, err
	}
	opts := exposure.Options{Ifaces: ifaces, FailOnPossible: *failPossible, Workers: *workers}
	if *expectFile != "" {
		f, err := os.Open(*expectFile)
		if err != nil {
			return exitError, err
		}
		opts.Expect, err = expect.Parse(f)
		f.Close()
		if err != nil {
			return exitError, fmt.Errorf("%s: %w", *expectFile, err)
		}
	}
	rep, err := exposure.Analyze(ctx, snap, opts)
	if err != nil {
		return exitError, err
	}
	if *format == "json" {
		err = report.JSON(stdout, rep)
	} else {
		err = report.Text(stdout, rep, *verbose)
	}
	if err != nil {
		return exitError, err
	}
	if rep.Violations() > 0 {
		return exitViolation, nil
	}
	return exitOK, nil
}

func explain(ctx context.Context, args []string, stdout io.Writer) error {
	fs := newFlags("explain")
	portFlag := fs.String("port", "", "proto/port, e.g. tcp/5432")
	fromFlag := fs.String("from", "", "source address (default: a documentation address standing for the internet)")
	ifaceFlag := fs.String("iface", "", "interface the packet arrives on (default: first external)")
	toFlag := fs.String("to", "", "destination address (default: first address of the interface)")
	dir, err := parse(fs, args)
	if err != nil {
		return err
	}
	proto, port, err := parsePort(*portFlag)
	if err != nil {
		return err
	}
	snap, err := snapshot.Load(dir)
	if err != nil {
		return err
	}
	iface := *ifaceFlag
	if iface == "" {
		ext := snap.ExternalIfaces()
		if len(ext) == 0 {
			return fmt.Errorf("%w: no external interface found, pass -iface", errUsage)
		}
		iface = ext[0]
	}
	ifc, ok := snap.Iface(iface)
	if !ok {
		return fmt.Errorf("%q: %w", iface, exposure.ErrUnknownIface)
	}
	src, dst, err := endpoints(*fromFlag, *toFlag, ifc)
	if err != nil {
		return err
	}
	pkt := netpkt.NewInbound(proto, src, dst, port, iface)
	res, err := exposure.Explain(ctx, snap, pkt)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s/%d from %s to %s on %s: %d outcome(s)\n", proto, port, src, dst, iface, len(res))
	for i, e := range res {
		o := e.Outcome
		verdict := "undecided"
		switch {
		case e.Sink != "":
			verdict = "delivered to " + e.Sink
		case o.Delivered():
			verdict = fmt.Sprintf("accepted, but nothing listens on %s:%d", o.Packet.Dst, o.Packet.DstPort)
		case o.Decided:
			verdict = o.Verdict.String()
		}
		fmt.Fprintf(stdout, "\n#%d %s\n", i+1, verdict)
		report.TraceLines(stdout, o.Trace)
		for _, as := range o.Assumed {
			fmt.Fprintf(stdout, "  %-11s %s (matched=%v)\n", "assumed", as.Step.Describe(), as.Matched)
		}
		for _, n := range e.Notes {
			fmt.Fprintf(stdout, "  %-11s %s\n", "note", n)
		}
		for _, h := range e.Hints {
			fmt.Fprintf(stdout, "  %-11s %s\n  %-11s see %s\n", "fix", strings.ReplaceAll(h.Text, "\n", "\n              "), "", h.Doc)
		}
	}
	return nil
}

func parsePort(s string) (netpkt.Proto, uint16, error) {
	ps, ports, ok := strings.Cut(s, "/")
	if !ok {
		return 0, 0, fmt.Errorf("%w: -port wants proto/port, got %q", errUsage, s)
	}
	proto, err := netpkt.ParseProto(ps)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: %w", errUsage, err)
	}
	n, err := strconv.ParseUint(ports, 10, 16)
	if err != nil || n == 0 {
		return 0, 0, fmt.Errorf("%w: port %q", errUsage, ports)
	}
	return proto, uint16(n), nil
}

func endpoints(from, to string, ifc netpkt.Iface) (netip.Addr, netip.Addr, error) {
	var src, dst netip.Addr
	var err error
	if from != "" {
		if src, err = netip.ParseAddr(from); err != nil {
			return src, dst, fmt.Errorf("%w: -from: %w", errUsage, err)
		}
	}
	if to != "" {
		if dst, err = netip.ParseAddr(to); err != nil {
			return src, dst, fmt.Errorf("%w: -to: %w", errUsage, err)
		}
	}
	if !dst.IsValid() {
		for _, a := range snapshot.GlobalAddrs(ifc) {
			if !src.IsValid() || netpkt.FamilyOf(a) == netpkt.FamilyOf(src) {
				dst = a
				break
			}
		}
		if !dst.IsValid() {
			return src, dst, fmt.Errorf("%w: %s has no usable address, pass -to", errUsage, ifc.Name)
		}
	}
	if !src.IsValid() {
		src = srcclass.Sample(netpkt.FamilyOf(dst))
	}
	if netpkt.FamilyOf(src) != netpkt.FamilyOf(dst) {
		return src, dst, fmt.Errorf("%w: -from and -to are different address families", errUsage)
	}
	return src, dst, nil
}
