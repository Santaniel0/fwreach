package exposure

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Santaniel0/fwreach/internal/expect"
	"github.com/Santaniel0/fwreach/internal/netpkt"
	"github.com/Santaniel0/fwreach/internal/ruleset"
	"github.com/Santaniel0/fwreach/internal/snapshot"
	"github.com/Santaniel0/fwreach/internal/srcclass"
)

const snapshots = "../../testdata/snapshots"

func load(t *testing.T, dir string) *snapshot.Snapshot {
	t.Helper()
	s, err := snapshot.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func expectations(t *testing.T) *expect.Set {
	t.Helper()
	f, err := os.Open("../../testdata/expect.conf")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	set, err := expect.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// variant copies a fixture into a temp dir, letting edit rewrite files.
func variant(t *testing.T, name string, edit func(file, data string) string) string {
	t.Helper()
	src := filepath.Join(snapshots, name)
	dst := t.TempDir()
	ents, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), []byte(edit(e.Name(), string(b))), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func replace(t *testing.T, data, old, new string) string {
	t.Helper()
	if !strings.Contains(data, old) {
		t.Fatalf("fixture does not contain %q", old)
	}
	return strings.Replace(data, old, new, 1)
}

func find(t *testing.T, rep *Report, port uint16) Finding {
	t.Helper()
	for _, f := range rep.Findings {
		if f.Port == port && f.Family == netpkt.IPv4 {
			return f
		}
	}
	t.Fatalf("no finding for port %d", port)
	return Finding{}
}

func reachString(rs []Reach) string {
	var parts []string
	for _, r := range rs {
		for _, rg := range r.Ranges {
			for _, p := range srcclass.Prefixes(rg) {
				parts = append(parts, p.String()+"@"+r.Iface)
			}
		}
	}
	return strings.Join(parts, " ")
}

func TestUfwDockerBypass(t *testing.T) {
	rep, err := Analyze(context.Background(), load(t, filepath.Join(snapshots, "ubuntu-ufw-docker")), Options{Expect: expectations(t)})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		port    uint16
		status  Status
		expect  Expectation
		path    netpkt.Hook
		allowed string
	}{
		{22, StatusExposed, ExpectOK, netpkt.Input, "0.0.0.0/0@eth0"},
		{80, StatusExposed, ExpectOK, netpkt.Forward, "0.0.0.0/0@eth0"},
		{5432, StatusExposed, ExpectViolation, netpkt.Forward, "0.0.0.0/0@eth0"},
		{6379, StatusFiltered, ExpectOK, 0, ""},
		{9100, StatusExposed, ExpectOK, netpkt.Input, "10.0.0.0/8@eth0"},
	}
	for _, tc := range cases {
		f := find(t, rep, tc.port)
		if f.Status != tc.status || f.Expect != tc.expect || f.Path != tc.path || reachString(f.Allowed) != tc.allowed {
			t.Errorf("port %d: status=%v expect=%v path=%v allowed=%q, want %v %v %v %q",
				tc.port, f.Status, f.Expect, f.Path, reachString(f.Allowed), tc.status, tc.expect, tc.path, tc.allowed)
		}
	}
	if rep.Violations() != 1 {
		t.Fatalf("want 1 violation, got %d", rep.Violations())
	}
	db := find(t, rep, 5432)
	if db.Sink != "container app-db-1 172.18.0.3:5432" {
		t.Errorf("sink %q", db.Sink)
	}
	if len(db.Notes) != 1 || !strings.Contains(db.Notes[0], `ufw-user-input #4 "-p tcp -m tcp --dport 5432 -j DROP"`) {
		t.Errorf("want the ufw deny rule named in a note, got %q", db.Notes)
	}
	want := "iptables -I DOCKER-USER " + DockerUserRule("eth0", netpkt.ProtoTCP, 5432)
	if len(db.Hints) != 2 || db.Hints[0].Text != want || db.Hints[0].Doc != docDockerUser {
		t.Errorf("hints %+v, want first %q", db.Hints, want)
	}
}

// The fixed fixture is the bypass fixture plus exactly the rule the hint
// prints, the way iptables-save shows it after "iptables -I DOCKER-USER".
func TestDockerUserHintFlipsVerdict(t *testing.T) {
	dir := filepath.Join(snapshots, "ubuntu-ufw-docker-fixed")
	b, err := os.ReadFile(filepath.Join(dir, snapshot.FileIPTables))
	if err != nil {
		t.Fatal(err)
	}
	rule := "-A DOCKER-USER " + DockerUserRule("eth0", netpkt.ProtoTCP, 5432) + "\n"
	if !strings.Contains(string(b), rule) {
		t.Fatalf("fixed fixture must contain the hint's rule %q", rule)
	}
	rep, err := Analyze(context.Background(), load(t, dir), Options{Expect: expectations(t)})
	if err != nil {
		t.Fatal(err)
	}
	if f := find(t, rep, 5432); f.Status != StatusFiltered || rep.Violations() != 0 {
		t.Fatalf("5432 after fix: %v, violations %d", f.Status, rep.Violations())
	}
	if f := find(t, rep, 80); f.Status != StatusExposed {
		t.Fatalf("the fix must not touch other ports, 80 is %v", f.Status)
	}
}

// Replays the loopback hint: these are the rules Docker generates for
// "-p 127.0.0.1:5432:5432" (moby iptablesdoc usernet-portmap-lo), and the
// listener docker-proxy then opens.
func TestLoopbackHintFlipsVerdict(t *testing.T) {
	dir := variant(t, "ubuntu-ufw-docker", func(file, data string) string {
		switch file {
		case snapshot.FileIPTables:
			data = replace(t, data, "-A DOCKER ! -i br-5c1e9a3f0b2d -p tcp -m tcp --dport 5432",
				"-A DOCKER -d 127.0.0.1/32 ! -i br-5c1e9a3f0b2d -p tcp -m tcp --dport 5432")
			data = replace(t, data, "-A PREROUTING -d 127.0.0.1/32 ! -i lo -p tcp -m tcp --dport 6379 -j DROP\n",
				"-A PREROUTING -d 127.0.0.1/32 ! -i lo -p tcp -m tcp --dport 6379 -j DROP\n-A PREROUTING -d 127.0.0.1/32 ! -i lo -p tcp -m tcp --dport 5432 -j DROP\n")
		case snapshot.FileSS:
			data = replace(t, data, "0.0.0.0:5432", "127.0.0.1:5432")
			data = replace(t, data, "tcp   LISTEN 0      4096                [::]:5432          [::]:*    users:((\"docker-proxy\",pid=2238,fd=7))\n", "")
		case snapshot.FileDocker:
			data = replace(t, data, `[{"HostIp": "0.0.0.0", "HostPort": "5432"}, {"HostIp": "::", "HostPort": "5432"}]`,
				`[{"HostIp": "127.0.0.1", "HostPort": "5432"}]`)
		}
		return data
	})
	rep, err := Analyze(context.Background(), load(t, dir), Options{Expect: expectations(t)})
	if err != nil {
		t.Fatal(err)
	}
	if f := find(t, rep, 5432); f.Status == StatusExposed || f.Status == StatusPossible || rep.Violations() != 0 {
		t.Fatalf("5432 published on loopback: %v, violations %d", f.Status, rep.Violations())
	}
}

// "ufw limit 22/tcp" relies on -m recent, which fwreach cannot evaluate.
func TestUnknownMatchMakesFindingPossible(t *testing.T) {
	dir := variant(t, "ubuntu-ufw-docker", func(file, data string) string {
		if file != snapshot.FileIPTables {
			return data
		}
		return replace(t, data, "-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT\n",
			"-A ufw-user-input -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name DEFAULT --mask 255.255.255.255 --rsource\n"+
				"-A ufw-user-input -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 30 --hitcount 6 --name DEFAULT --mask 255.255.255.255 --rsource -j ufw-user-limit\n"+
				"-A ufw-user-input -p tcp -m tcp --dport 22 -j ufw-user-limit-accept\n")
	})
	rep, err := Analyze(context.Background(), load(t, dir), Options{Expect: expectations(t), FailOnPossible: true})
	if err != nil {
		t.Fatal(err)
	}
	f := find(t, rep, 22)
	if f.Status != StatusPossible || len(f.DependsOn) != 1 || f.DependsOn[0].Chain != "ufw-user-input" || f.DependsOn[0].Pos != 2 {
		t.Fatalf("22: %v depends on %+v", f.Status, f.DependsOn)
	}
	if f.Expect != ExpectOK {
		t.Fatalf("possible but expected exposure must not be a violation, got %v", f.Expect)
	}
}

func TestDeterministicAcrossWorkerCounts(t *testing.T) {
	snap := load(t, filepath.Join(snapshots, "ubuntu-ufw-docker"))
	var prev []string
	for _, w := range []int{1, 3, 16} {
		rep, err := Analyze(context.Background(), snap, Options{Workers: w})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range rep.Findings {
			var buf bytes.Buffer
			for _, s := range f.Example.Outcome.Trace {
				buf.WriteString(s.Describe() + "\n")
			}
			got = append(got, f.ProtoPort.String()+f.Status.String()+reachString(f.Allowed)+buf.String())
		}
		if prev != nil && !slices.Equal(prev, got) {
			t.Fatalf("output with %d workers differs", w)
		}
		prev = got
	}
}

func TestAnalyzeCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Analyze(ctx, load(t, filepath.Join(snapshots, "ubuntu-ufw-docker")), Options{Workers: 4})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestUnknownIface(t *testing.T) {
	_, err := Analyze(context.Background(), load(t, filepath.Join(snapshots, "ubuntu-ufw-docker")), Options{Ifaces: []string{"wlan9"}})
	if !errors.Is(err, ErrUnknownIface) {
		t.Fatalf("want ErrUnknownIface, got %v", err)
	}
}

func findFam(t *testing.T, rep *Report, port uint16, fam netpkt.Family) Finding {
	t.Helper()
	for _, f := range rep.Findings {
		if f.Port == port && f.Family == fam {
			return f
		}
	}
	t.Fatalf("no finding for port %d %v", port, fam)
	return Finding{}
}

// Docker 29 with the nftables backend and a Debian-style inet filter table
// whose forward rule tries to drop the published port.
func TestNftablesDockerPortRewrite(t *testing.T) {
	rep, err := Analyze(context.Background(), load(t, filepath.Join(snapshots, "debian-nft-docker29")), Options{Expect: expectations(t)})
	if err != nil {
		t.Fatal(err)
	}
	f := findFam(t, rep, 3000, netpkt.IPv4)
	if f.Status != StatusExposed || f.Expect != ExpectViolation || f.Sink != "container ai-webui-1 172.19.0.2:8080" {
		t.Fatalf("3000/v4: %v %v %q", f.Status, f.Expect, f.Sink)
	}
	if len(f.Notes) != 2 || !strings.Contains(f.Notes[0], "policy drop of inet filter input") ||
		!strings.Contains(f.Notes[1], `inet filter forward #1 "tcp dport 3000 drop" matches port 3000`) {
		t.Fatalf("notes %q", f.Notes)
	}
	if len(f.Hints) != 1 || f.Hints[0].Text != NftGuardTable("eth0", netpkt.ProtoTCP, 3000) || f.Hints[0].Doc != docNftables {
		t.Fatalf("hints %+v", f.Hints)
	}
	if f6 := findFam(t, rep, 3000, netpkt.IPv6); f6.Status != StatusFiltered {
		t.Fatalf("3000/v6 reaches docker-proxy through input, where policy drop applies; got %v", f6.Status)
	}
}

// guardJSON is the hint's table written in nft -j form, as nft would list it
// after `nft -f` of the hint text.
const guardJSON = `{"table": {"family": "inet", "name": "fwreach-guard", "handle": 9}},
 {"chain": {"family": "inet", "table": "fwreach-guard", "name": "forward", "handle": 1, "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"}},
 {"rule": {"family": "inet", "table": "fwreach-guard", "chain": "forward", "handle": 2, "expr": [
  {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "eth0"}},
  {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}},
  {"match": {"op": "==", "left": {"ct": {"key": "proto-dst", "dir": "original"}}, "right": 3000}},
  {"drop": null}]}},`

func TestNftGuardHintFlipsVerdict(t *testing.T) {
	dir := variant(t, "debian-nft-docker29", func(file, data string) string {
		if file != snapshot.FileNft {
			return data
		}
		return replace(t, data, `{"nftables": [`, `{"nftables": [`+guardJSON)
	})
	snap := load(t, dir)
	var guard string
	for _, tb := range snap.Ruleset.Tables {
		if tb.Name == "fwreach-guard" {
			guard = tb.Chains[0].Rules[0].Text
		}
	}
	if want := GuardTable("eth0", netpkt.ProtoTCP, 3000).Chains[0].Rules[0].Text; guard != want {
		t.Fatalf("hint text and its JSON form disagree:\n json: %q\n hint: %q", guard, want)
	}
	rep, err := Analyze(context.Background(), snap, Options{Expect: expectations(t)})
	if err != nil {
		t.Fatal(err)
	}
	if f := findFam(t, rep, 3000, netpkt.IPv4); f.Status != StatusFiltered || rep.Violations() != 0 {
		t.Fatalf("3000 with the guard table: %v, violations %d", f.Status, rep.Violations())
	}
	if f := findFam(t, rep, 22, netpkt.IPv4); f.Status != StatusExposed {
		t.Fatalf("guard must not affect ssh, got %v", f.Status)
	}
}

// Docker's nftables docs: a legacy iptables FORWARD policy DROP left over
// from the iptables backend drops what Docker's nft rules accept.
func TestLegacyForwardPolicyDropsNftAccept(t *testing.T) {
	dir := variant(t, "debian-nft-docker29", func(_, data string) string { return data })
	legacy := "# Generated by iptables-save v1.8.11 on Mon Nov  9 11:40:00 2026\n*filter\n" +
		":INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
	if err := os.WriteFile(filepath.Join(dir, snapshot.FileIPTablesLegacy), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := Analyze(context.Background(), load(t, dir), Options{})
	if err != nil {
		t.Fatal(err)
	}
	f := findFam(t, rep, 3000, netpkt.IPv4)
	by := f.Example.Outcome.By
	if f.Status != StatusFiltered || by == nil || by.Source != ruleset.SourceIPTablesLegacy || by.Chain != "FORWARD" {
		t.Fatalf("3000: %v decided by %+v", f.Status, by)
	}
	if f := findFam(t, rep, 22, netpkt.IPv4); f.Status != StatusExposed {
		t.Fatalf("legacy INPUT ACCEPT must not change ssh, got %v", f.Status)
	}
}
