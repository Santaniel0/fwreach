package srcclass

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/Santaniel0/fwreach/internal/netpkt"
)

func pfx(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestPartition(t *testing.T) {
	cases := []struct {
		name  string
		fam   netpkt.Family
		in    []netip.Prefix
		froms []string
		reps  []string
	}{
		{"no prefixes is one class", netpkt.IPv4, nil, []string{"0.0.0.0"}, []string{"198.51.100.7"}},
		{"one private range", netpkt.IPv4, pfx("10.0.0.0/8"),
			[]string{"0.0.0.0", "10.0.0.0", "11.0.0.0"}, []string{"0.0.0.1", "10.0.0.0", "198.51.100.7"}},
		{"nested and duplicate prefixes", netpkt.IPv4, pfx("10.0.0.0/8", "10.1.0.0/16", "10.0.0.0/8"),
			[]string{"0.0.0.0", "10.0.0.0", "10.1.0.0", "10.2.0.0", "11.0.0.0"}, nil},
		{"host route at the top of the space", netpkt.IPv4, pfx("255.255.255.255/32"),
			[]string{"0.0.0.0", "255.255.255.255"}, nil},
		{"default route adds nothing", netpkt.IPv4, pfx("0.0.0.0/0"), []string{"0.0.0.0"}, nil},
		{"other family ignored", netpkt.IPv4, pfx("2001:db8::/32"), []string{"0.0.0.0"}, nil},
		{"ipv6", netpkt.IPv6, pfx("fd00::/8", "2001:db8::/32"),
			[]string{"::", "2001:db8::", "2001:db9::", "fd00::", "fe00::"},
			[]string{"::1", "2001:db8:ffff::7", "2001:db9::", "fd00::", "fe00::"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cls := Partition(tc.fam, tc.in)
			var froms, reps []string
			for i, c := range cls {
				froms = append(froms, c.From.String())
				reps = append(reps, c.Rep.String())
				if !c.Contains(c.Rep) {
					t.Errorf("class %d: rep %v outside %v-%v", i, c.Rep, c.From, c.To)
				}
				if i > 0 && cls[i-1].To.Next() != c.From {
					t.Errorf("gap or overlap before class %d", i)
				}
			}
			if !slices.Equal(froms, tc.froms) {
				t.Errorf("starts %v, want %v", froms, tc.froms)
			}
			if tc.reps != nil && !slices.Equal(reps, tc.reps) {
				t.Errorf("reps %v, want %v", reps, tc.reps)
			}
			lo, hi := bounds(tc.fam)
			if cls[0].From != lo || cls[len(cls)-1].To != hi {
				t.Errorf("partition does not cover the space")
			}
		})
	}
}

func r(from, to string) Range {
	return Range{From: netip.MustParseAddr(from), To: netip.MustParseAddr(to)}
}

func TestMergeAndPrefixes(t *testing.T) {
	cases := []struct {
		name string
		in   []Range
		want []string
	}{
		{"adjacent ranges join", []Range{r("10.128.0.0", "10.255.255.255"), r("10.0.0.0", "10.127.255.255")}, []string{"10.0.0.0/8"}},
		{"everything", []Range{r("0.0.0.0", "9.255.255.255"), r("10.0.0.0", "255.255.255.255")}, []string{"0.0.0.0/0"}},
		{"everything except 10/8", []Range{r("0.0.0.0", "9.255.255.255"), r("11.0.0.0", "255.255.255.255")},
			[]string{"0.0.0.0/5", "8.0.0.0/7", "11.0.0.0/8", "12.0.0.0/6", "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1"}},
		{"unaligned", []Range{r("192.0.2.1", "192.0.2.6")}, []string{"192.0.2.1/32", "192.0.2.2/31", "192.0.2.4/31", "192.0.2.6/32"}},
		{"overlap", []Range{r("192.0.2.0", "192.0.2.200"), r("192.0.2.100", "192.0.2.255")}, []string{"192.0.2.0/24"}},
		{"ipv6 top of space", []Range{r("ff00::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")}, []string{"ff00::/8"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, m := range Merge(tc.in) {
				for _, p := range Prefixes(m) {
					got = append(got, p.String())
				}
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
	if !IsAll(netpkt.IPv4, Merge([]Range{r("0.0.0.0", "9.255.255.255"), r("10.0.0.0", "255.255.255.255")})) {
		t.Fatal("IsAll should hold for the full v4 space")
	}
}
