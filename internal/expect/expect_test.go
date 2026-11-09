package expect

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/Santaniel0/fwreach/internal/netpkt"
)

func TestParseAndAllows(t *testing.T) {
	set, err := Parse(strings.NewReader(`
# comment
allow tcp/22 from any
allow tcp/80,443,8000-8002 from any   # trailing comment
allow tcp/9100 from 10.0.0.0/8, 192.168.1.5
allow udp/51820 from 2001:db8::/32
`))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		pp   ProtoPort
		src  string
		want bool
	}{
		{ProtoPort{netpkt.ProtoTCP, 22}, "198.51.100.7", true},
		{ProtoPort{netpkt.ProtoTCP, 22}, "2001:db8::1", true},
		{ProtoPort{netpkt.ProtoUDP, 22}, "198.51.100.7", false},
		{ProtoPort{netpkt.ProtoTCP, 8001}, "198.51.100.7", true},
		{ProtoPort{netpkt.ProtoTCP, 9100}, "10.20.30.40", true},
		{ProtoPort{netpkt.ProtoTCP, 9100}, "192.168.1.5", true},
		{ProtoPort{netpkt.ProtoTCP, 9100}, "192.168.1.6", false},
		{ProtoPort{netpkt.ProtoUDP, 51820}, "198.51.100.7", false},
	}
	for _, tc := range cases {
		if got := set.Allows(tc.pp, netip.MustParseAddr(tc.src)); got != tc.want {
			t.Errorf("%v from %s: got %v, want %v", tc.pp, tc.src, got, tc.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{
		"deny tcp/22 from any",
		"allow tcp22 from any",
		"allow sctp/22 from any",
		"allow tcp/0 from any",
		"allow tcp/90-80 from any",
		"allow tcp/22 from",
		"allow tcp/22 from 10.0.0.0/33",
	} {
		if _, err := Parse(strings.NewReader(in)); !errors.Is(err, ErrSyntax) {
			t.Errorf("%q: want ErrSyntax, got %v", in, err)
		}
	}
}
