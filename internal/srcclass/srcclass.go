// Package srcclass splits an address space into classes that every rule
// treats the same way, so one representative per class is enough.
//
// Each prefix a rule mentions cuts the space at its first address and just
// past its last one. Between two consecutive cuts no prefix starts or ends,
// so every address-based match gives the same answer for all of them.
package srcclass

import (
	"net/netip"
	"slices"

	"github.com/Santaniel0/fwreach/internal/netpkt"
)

// Range is an inclusive address interval.
type Range struct{ From, To netip.Addr }

// Class is one interval of the partition with the address that stands in
// for it during simulation.
type Class struct {
	Range
	Rep netip.Addr
}

// Samples are preferred representatives. They are documentation addresses,
// so a trace never shows a real third party.
var samples = map[netpkt.Family]netip.Addr{
	netpkt.IPv4: netip.MustParseAddr("198.51.100.7"),
	netpkt.IPv6: netip.MustParseAddr("2001:db8:ffff::7"),
}

// Sample returns the address used to stand for "anywhere on the internet".
func Sample(fam netpkt.Family) netip.Addr { return samples[fam] }

func bounds(fam netpkt.Family) (netip.Addr, netip.Addr) {
	if fam == netpkt.IPv4 {
		return netip.IPv4Unspecified(), netip.AddrFrom4([4]byte{255, 255, 255, 255})
	}
	return netip.IPv6Unspecified(), netpkt.LastAddr(netip.MustParsePrefix("::/0"))
}

// Partition returns the classes for fam induced by prefixes; prefixes of
// the other family are ignored. The result covers the whole space in order.
func Partition(fam netpkt.Family, prefixes []netip.Prefix) []Class {
	lo, hi := bounds(fam)
	cuts := []netip.Addr{lo}
	for _, p := range prefixes {
		if netpkt.FamilyOf(p.Addr()) != fam || p.Addr().Is4In6() {
			continue
		}
		p = p.Masked()
		cuts = append(cuts, p.Addr())
		if next := netpkt.LastAddr(p).Next(); next.IsValid() {
			cuts = append(cuts, next)
		}
	}
	slices.SortFunc(cuts, netip.Addr.Compare)
	cuts = slices.Compact(cuts)
	out := make([]Class, 0, len(cuts))
	for i, from := range cuts {
		to := hi
		if i+1 < len(cuts) {
			to = cuts[i+1].Prev()
		}
		r := Range{From: from, To: to}
		out = append(out, Class{Range: r, Rep: rep(fam, r)})
	}
	return out
}

func rep(fam netpkt.Family, r Range) netip.Addr {
	if s := samples[fam]; r.Contains(s) {
		return s
	}
	if r.From.IsUnspecified() && r.From != r.To {
		return r.From.Next()
	}
	return r.From
}

// Contains reports whether a lies in r.
func (r Range) Contains(a netip.Addr) bool {
	return r.From.BitLen() == a.BitLen() && r.From.Compare(a) <= 0 && a.Compare(r.To) <= 0
}

// Merge sorts ranges and joins overlapping or adjacent ones.
func Merge(rs []Range) []Range {
	rs = slices.Clone(rs)
	slices.SortFunc(rs, func(a, b Range) int { return a.From.Compare(b.From) })
	var out []Range
	for _, r := range rs {
		if n := len(out); n > 0 {
			last := &out[n-1]
			if next := last.To.Next(); !next.IsValid() || r.From.Compare(next) <= 0 {
				if r.To.Compare(last.To) > 0 {
					last.To = r.To
				}
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// Prefixes returns the smallest list of CIDR blocks that exactly covers r.
func Prefixes(r Range) []netip.Prefix {
	var out []netip.Prefix
	start := r.From
	for {
		var p netip.Prefix
		for bits := 0; bits <= start.BitLen(); bits++ {
			cand := netip.PrefixFrom(start, bits)
			if cand.Masked().Addr() == start && netpkt.LastAddr(cand).Compare(r.To) <= 0 {
				p = cand
				break
			}
		}
		out = append(out, p)
		last := netpkt.LastAddr(p)
		if last == r.To {
			return out
		}
		start = last.Next()
	}
}

// IsAll reports whether rs, already merged, is the whole space of fam.
func IsAll(fam netpkt.Family, rs []Range) bool {
	lo, hi := bounds(fam)
	return len(rs) == 1 && rs[0].From == lo && rs[0].To == hi
}
