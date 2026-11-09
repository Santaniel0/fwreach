package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

const (
	snaps      = "../../testdata/snapshots/"
	expectFile = "../../testdata/expect.conf"
)

func runCLI(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestAnalyzeGolden(t *testing.T) {
	cases := []struct {
		golden string
		args   []string
		code   int
	}{
		{"ubuntu-ufw-docker.golden", []string{"analyze", "-expect", expectFile, snaps + "ubuntu-ufw-docker"}, exitViolation},
		{"ubuntu-ufw-docker-fixed.golden", []string{"analyze", "-expect", expectFile, snaps + "ubuntu-ufw-docker-fixed"}, exitOK},
	}
	for _, tc := range cases {
		t.Run(tc.golden, func(t *testing.T) {
			code, out, errOut := runCLI(tc.args...)
			if code != tc.code {
				t.Fatalf("exit %d, want %d; stderr: %s", code, tc.code, errOut)
			}
			path := filepath.Join("testdata", tc.golden)
			if *update {
				if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if out != string(want) {
				t.Fatalf("output differs from %s (run with -update to accept):\n%s", path, out)
			}
		})
	}
}

func TestAnalyzeJSON(t *testing.T) {
	code, out, errOut := runCLI("analyze", "-format", "json", "-expect", expectFile, snaps+"ubuntu-ufw-docker")
	if code != exitViolation {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	var doc struct {
		Violations int `json:"violations"`
		Findings   []struct {
			Port        string `json:"port"`
			Expectation string `json:"expectation"`
			Hints       []struct {
				Text string `json:"text"`
			} `json:"hints"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Violations != 1 {
		t.Fatalf("violations %d", doc.Violations)
	}
	for _, f := range doc.Findings {
		if f.Port == "tcp/5432" && (f.Expectation != "unexpected" || len(f.Hints) == 0) {
			t.Fatalf("tcp/5432: %+v", f)
		}
	}
}

func TestExplain(t *testing.T) {
	code, out, errOut := runCLI("explain", "-port", "tcp/5432", snaps+"ubuntu-ufw-docker")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"tcp/5432 from 198.51.100.7 to 203.0.113.10 on eth0: 1 outcome(s)",
		"delivered to container app-db-1 172.18.0.3:5432",
		"DNAT --to-destination 172.18.0.3:5432",
		"iptables -I DOCKER-USER -i eth0 -p tcp -m conntrack --ctorigdstport 5432 -j DROP",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("explain output lacks %q:\n%s", want, out)
		}
	}
	code, out, _ = runCLI("explain", "-port", "tcp/9100", "-from", "10.1.2.3", snaps+"ubuntu-ufw-docker")
	if code != exitOK || !strings.Contains(out, "delivered to node_exporter on *") {
		t.Fatalf("9100 from 10/8: exit %d\n%s", code, out)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"frobnicate"},
		{"analyze"},
		{"analyze", "-format", "yaml", snaps + "ubuntu-ufw-docker"},
		{"analyze", "-iface", "wlan9", snaps + "ubuntu-ufw-docker"},
		{"analyze", t.TempDir()},
		{"explain", "-port", "5432", snaps + "ubuntu-ufw-docker"},
		{"explain", "-port", "tcp/22", "-from", "2001:db8::1", "-to", "203.0.113.10", snaps + "ubuntu-ufw-docker"},
	} {
		if code, _, errOut := runCLI(args...); code != exitError || errOut == "" {
			t.Errorf("%v: exit %d, stderr %q", args, code, errOut)
		}
	}
}
