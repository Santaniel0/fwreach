package nftjson

import (
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/Santaniel0/fwreach/internal/netpkt"
	"github.com/Santaniel0/fwreach/internal/ruleset"
)

func parseFile(t *testing.T, path string) *Result {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestParseDockerBridges(t *testing.T) {
	res := parseFile(t, "../../testdata/snapshots/debian-nft-docker29/nft.json")
	if len(res.Tables) != 2 || len(res.Warnings) != 0 {
		t.Fatalf("tables %d warnings %v", len(res.Tables), res.Warnings)
	}
	db := res.Tables[1]
	if db.ID() != "ip docker-bridges" {
		t.Fatalf("second table is %s", db.ID())
	}
	bases := map[string]ruleset.BaseChain{
		"raw-PREROUTING": {Hook: netpkt.Prerouting, Kind: ruleset.KindFilter, Priority: -300, Policy: ruleset.Accept},
		"nat-PREROUTING": {Hook: netpkt.Prerouting, Kind: ruleset.KindNAT, Priority: -100, Policy: ruleset.Accept},
		"filter-FORWARD": {Hook: netpkt.Forward, Kind: ruleset.KindFilter, Priority: 0, Policy: ruleset.Accept},
	}
	for name, want := range bases {
		if c := db.Chain(name); c == nil || c.Base == nil || *c.Base != want {
			t.Errorf("%s: %+v, want %+v", name, c, want)
		}
	}
	fwd := db.Chain("filter-FORWARD").Rules
	if len(fwd) != 4 || fwd[0].Pos != 1 || fwd[1].Pos != 1 || fwd[2].Pos != 2 {
		t.Fatalf("two vmaps with two elements each should give 4 rules at positions 1,1,2,2: %+v", fwd)
	}
	dnat := db.Chain("nat-prerouting-and-output").Rules[0]
	if dnat.Action.Kind != ruleset.ActDNAT || dnat.Action.DNATAddr != netip.MustParseAddr("172.19.0.2") || dnat.Action.DNATPort != 8080 {
		t.Fatalf("dnat rule %+v", dnat.Action)
	}
	if want := `iifname != "br-7d2c41f0e9a8" tcp dport 3000 counter dnat to 172.19.0.2:8080 comment "DNAT"`; dnat.Text != want {
		t.Fatalf("text %q, want %q", dnat.Text, want)
	}
}

func TestMatchSemantics(t *testing.T) {
	host := &netpkt.Host{Ifaces: []netpkt.Iface{{Name: "eth0", Addrs: []netip.Prefix{netip.MustParsePrefix("203.0.113.20/24")}}}}
	pkt := netpkt.NewInbound(netpkt.ProtoTCP, netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("203.0.113.20"), 3000, "eth0")
	cases := []struct {
		expr string
		want netpkt.Tristate
	}{
		{`{"match":{"op":"==","left":{"payload":{"protocol":"th","field":"dport"}},"right":{"set":[22,{"range":[2999,3001]}]}}}`, netpkt.Yes},
		{`{"match":{"op":"!=","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":3000}}`, netpkt.No},
		{`{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":3000}}`, netpkt.No},
		{`{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"198.51.100.0","len":24}}}}`, netpkt.Yes},
		{`{"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"saddr"}},"right":"2001:db8::1"}}`, netpkt.No},
		{`{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":{"set":["wg0","eth*"]}}}`, netpkt.Yes},
		{`{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":{"set":["udp","tcp"]}}}`, netpkt.Yes},
		{`{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv6"}}`, netpkt.No},
		{`{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}}`, netpkt.No},
		{`{"match":{"op":"==","left":{"ct":{"key":"state"}},"right":"new"}}`, netpkt.Yes},
		{`{"match":{"op":"==","left":{"fib":{"result":"type","flags":["daddr"]}},"right":"local"}}`, netpkt.Yes},
		{`{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},3]},"right":1}}`, netpkt.No},
		{`{"match":{"op":"==","left":{"meta":{"key":"skuid"}},"right":0}}`, netpkt.Unknown},
		{`{"match":{"op":"<","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":1024}}`, netpkt.Unknown},
		{`{"xt":{"type":"match","name":"addrtype"}}`, netpkt.Unknown},
		{`{"limit":{"rate":3,"per":"minute"}}`, netpkt.Unknown},
	}
	for _, tc := range cases {
		doc := `{"nftables":[{"table":{"family":"inet","name":"t"}},` +
			`{"chain":{"family":"inet","table":"t","name":"c","type":"filter","hook":"input","prio":0,"policy":"accept"}},` +
			`{"rule":{"family":"inet","table":"t","chain":"c","expr":[` + tc.expr + `,{"drop":null}]}}]}`
		res, err := Parse(strings.NewReader(doc))
		if err != nil {
			t.Fatalf("%s: %v", tc.expr, err)
		}
		r := res.Tables[0].Chains[0].Rules[0]
		if got := ruleset.EvalAll(r.Matches, &pkt, host); got != tc.want {
			t.Errorf("%s (%s): got %v, want %v", tc.expr, r.Text, got, tc.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{
		`not json`,
		`{"something":[]}`,
		`{"nftables":[{"table":{"family":"ip","name":"t"}},{"rule":{"family":"ip","table":"t","chain":"nope","expr":[]}}]}`,
		`{"nftables":[{"table":{"family":"ip","name":"t"}},{"chain":{"family":"ip","table":"t","name":"c"}},` +
			`{"rule":{"family":"ip","table":"t","chain":"c","expr":[{"jump":{}}]}}]}`,
	} {
		if _, err := Parse(strings.NewReader(in)); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: want ErrFormat, got %v", in, err)
		}
	}
}
