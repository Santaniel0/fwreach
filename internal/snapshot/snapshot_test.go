package snapshot

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/Santaniel0/fwreach/internal/netpkt"
)

func TestParseSSAndAccepts(t *testing.T) {
	in := `udp   UNCONN 0      0          127.0.0.53%lo:53         0.0.0.0:*    users:(("systemd-resolve",pid=612,fd=13))
tcp   LISTEN 0      4096             0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=901,fd=3))
tcp   LISTEN 0      4096                [::]:443           [::]:*    users:(("docker-proxy",pid=2229,fd=7))
tcp   LISTEN 0      4096                   *:9100             *:*    users:(("node_exporter",pid=777,fd=3))
tcp   LISTEN 0      511    [::ffff:10.0.0.5]:8080              *:*
`
	ls, err := ParseSS(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 5 || ls[0].Iface != "lo" || ls[0].Process != "systemd-resolve" || ls[3].Wildcard != true || ls[4].Process != "" {
		t.Fatalf("parsed %+v", ls)
	}
	v4, v6 := netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("2001:db8::10")
	cases := []struct {
		l     Listener
		dst   netip.Addr
		iface string
		want  bool
	}{
		{ls[0], netip.MustParseAddr("127.0.0.53"), "eth0", false},
		{ls[1], v4, "eth0", true},
		{ls[1], v6, "eth0", false},
		{ls[2], v4, "eth0", true},
		{ls[2], v6, "eth0", true},
		{ls[3], v6, "eth0", true},
		{ls[4], netip.MustParseAddr("10.0.0.5"), "eth0", true},
		{ls[4], v4, "eth0", false},
	}
	for i, tc := range cases {
		if got := tc.l.Accepts(tc.dst, tc.iface); got != tc.want {
			t.Errorf("case %d: %s accepts %v = %v, want %v", i, tc.l.Bound(), tc.dst, got, tc.want)
		}
	}
	if _, err := ParseSS(strings.NewReader("tcp LISTEN 0 1 nonsense *:*\n")); err == nil {
		t.Fatal("want an error for a local address without a port")
	}
}

func TestLoadFixture(t *testing.T) {
	s, err := Load("../../testdata/snapshots/ubuntu-ufw-docker")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.ExternalIfaces(); len(got) != 1 || got[0] != "eth0" {
		t.Fatalf("external interfaces %v, want [eth0]", got)
	}
	if len(s.Families) != 1 || s.Families[0] != netpkt.IPv4 {
		t.Fatalf("families %v", s.Families)
	}
	c, ok := s.ContainerByIP(netip.MustParseAddr("172.18.0.3"))
	if !ok || c.Name != "app-db-1" || len(c.Ports) != 2 || c.Ports[0].HostIP.IsValid() {
		t.Fatalf("container %+v", c)
	}
	if _, err := Load(t.TempDir()); !errors.Is(err, ErrNoRuleset) {
		t.Fatalf("empty dir: want ErrNoRuleset, got %v", err)
	}
}
