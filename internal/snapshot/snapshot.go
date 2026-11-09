// Package snapshot loads the files `fwreach collect` writes (or that were
// captured by hand) into a ruleset and a host model.
package snapshot

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Santaniel0/fwreach/internal/iptables"
	"github.com/Santaniel0/fwreach/internal/netpkt"
	"github.com/Santaniel0/fwreach/internal/nftjson"
	"github.com/Santaniel0/fwreach/internal/ruleset"
)

// File names inside a snapshot directory.
const (
	FileManifest       = "manifest.json"
	FileIPTables       = "iptables-save.txt"
	FileIP6Tables      = "ip6tables-save.txt"
	FileIPTablesLegacy = "iptables-legacy-save.txt"
	FileIP6TablesLeg   = "ip6tables-legacy-save.txt"
	FileNft            = "nft.json"
	FileSS             = "ss.txt"
	FileIPAddr         = "ip-addr.json"
	FileDocker         = "docker-inspect.json"
)

// ErrNoRuleset means the directory had none of the ruleset files.
var ErrNoRuleset = errors.New("snapshot has no iptables-save or nft.json ruleset")

// Manifest describes how a snapshot was collected.
type Manifest struct {
	Host        string          `json:"host"`
	CollectedAt time.Time       `json:"collected_at"`
	Commands    []CommandResult `json:"commands"`
}

// CommandResult records one collection command.
type CommandResult struct {
	File    string `json:"file"`
	Command string `json:"command"`
	Error   string `json:"error,omitempty"`
}

// SourceInfo summarizes one loaded ruleset file.
type SourceInfo struct {
	File   string
	Source ruleset.Source
	Tables int
	Rules  int
}

// Snapshot is everything known about one host.
type Snapshot struct {
	Manifest   Manifest
	Ruleset    *ruleset.Ruleset
	Sources    []SourceInfo
	Families   []netpkt.Family // families some ruleset file covers
	Host       *netpkt.Host
	Listeners  []Listener
	Containers []Container
	Warnings   []string
}

// iptables-nft tables also show up in `nft -j list ruleset`, with their
// xt matches reduced to a name. When iptables-save is present it is the
// faithful copy, so these are dropped from the nft side.
var compatTables = map[string]bool{"filter": true, "nat": true, "raw": true, "mangle": true, "security": true}

// Load reads a snapshot directory. Missing optional files are fine.
func Load(dir string) (*Snapshot, error) {
	s := &Snapshot{Ruleset: &ruleset.Ruleset{}, Host: &netpkt.Host{}}
	if err := readJSON(dir, FileManifest, &s.Manifest); err != nil {
		return nil, err
	}
	fams := map[netpkt.Family]bool{}
	haveNftCompat := false
	for _, f := range []struct {
		name   string
		fam    netpkt.Family
		forced ruleset.Source
	}{
		{FileIPTables, netpkt.IPv4, 0},
		{FileIP6Tables, netpkt.IPv6, 0},
		{FileIPTablesLegacy, netpkt.IPv4, ruleset.SourceIPTablesLegacy},
		{FileIP6TablesLeg, netpkt.IPv6, ruleset.SourceIPTablesLegacy},
	} {
		err := withFile(dir, f.name, func(r io.Reader) error {
			res, err := iptables.Parse(r, f.fam, f.forced)
			if err != nil {
				return err
			}
			s.addTables(f.name, res.Source, res.Tables)
			s.Warnings = append(s.Warnings, prefixAll(f.name, res.Warnings)...)
			fams[f.fam] = true
			haveNftCompat = haveNftCompat || res.Source == ruleset.SourceIPTablesNft
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	err := withFile(dir, FileNft, func(r io.Reader) error {
		res, err := nftjson.Parse(r)
		if err != nil {
			return err
		}
		var keep []*ruleset.Table
		for _, t := range res.Tables {
			if haveNftCompat && t.Family != ruleset.FamilyInet && compatTables[t.Name] {
				continue
			}
			keep = append(keep, t)
			fams[netpkt.IPv4] = fams[netpkt.IPv4] || t.Family != ruleset.FamilyIP6
			fams[netpkt.IPv6] = fams[netpkt.IPv6] || t.Family != ruleset.FamilyIP
		}
		s.addTables(FileNft, ruleset.SourceNftables, keep)
		s.Warnings = append(s.Warnings, prefixAll(FileNft, res.Warnings)...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(s.Sources) == 0 {
		return nil, fmt.Errorf("%s: %w", dir, ErrNoRuleset)
	}
	for _, f := range []netpkt.Family{netpkt.IPv4, netpkt.IPv6} {
		if fams[f] {
			s.Families = append(s.Families, f)
		}
	}
	steps := []struct {
		name  string
		parse func(io.Reader) error
	}{
		{FileSS, func(r io.Reader) (err error) { s.Listeners, err = ParseSS(r); return }},
		{FileIPAddr, func(r io.Reader) (err error) { s.Host.Ifaces, err = ParseIPAddr(r); return }},
		{FileDocker, func(r io.Reader) (err error) { s.Containers, err = ParseDockerInspect(r); return }},
	}
	for _, st := range steps {
		if err := withFile(dir, st.name, st.parse); err != nil {
			return nil, err
		}
	}
	if len(s.Host.Ifaces) == 0 {
		s.Warnings = append(s.Warnings, FileIPAddr+" missing: no interfaces, nothing to probe")
	}
	if len(s.Listeners) == 0 {
		s.Warnings = append(s.Warnings, FileSS+" missing or empty: cannot tell which ports have a listener")
	}
	return s, nil
}

func (s *Snapshot) addTables(file string, src ruleset.Source, ts []*ruleset.Table) {
	info := SourceInfo{File: file, Source: src, Tables: len(ts)}
	for _, t := range ts {
		for _, c := range t.Chains {
			info.Rules += len(c.Rules)
		}
	}
	s.Ruleset.Tables = append(s.Ruleset.Tables, ts...)
	s.Sources = append(s.Sources, info)
}

// ExternalIfaces guesses which interfaces face other hosts: everything with
// a global address except loopback and container bridges.
func (s *Snapshot) ExternalIfaces() []string {
	var out []string
	for _, ifc := range s.Host.Ifaces {
		if ifc.Loopback || s.isBridge(ifc) {
			continue
		}
		if len(GlobalAddrs(ifc)) > 0 {
			out = append(out, ifc.Name)
		}
	}
	return out
}

func (s *Snapshot) isBridge(ifc netpkt.Iface) bool {
	if ifc.Name == "docker0" || strings.HasPrefix(ifc.Name, "br-") {
		return true
	}
	for _, c := range s.Containers {
		for _, ip := range c.IPs {
			for _, p := range ifc.Addrs {
				if p.Masked().Contains(ip) {
					return true
				}
			}
		}
	}
	return false
}

// Iface returns the named interface.
func (s *Snapshot) Iface(name string) (netpkt.Iface, bool) {
	for _, ifc := range s.Host.Ifaces {
		if ifc.Name == name {
			return ifc, true
		}
	}
	return netpkt.Iface{}, false
}

// GlobalAddrs returns the addresses of ifc usable as probe destinations.
func GlobalAddrs(ifc netpkt.Iface) []netip.Addr {
	var out []netip.Addr
	for _, p := range ifc.Addrs {
		a := p.Addr()
		if !a.IsLoopback() && !a.IsLinkLocalUnicast() {
			out = append(out, a)
		}
	}
	return out
}

// ContainerByIP finds the container owning addr.
func (s *Snapshot) ContainerByIP(addr netip.Addr) (Container, bool) {
	for _, c := range s.Containers {
		if slices.Contains(c.IPs, addr) {
			return c, true
		}
	}
	return Container{}, false
}

func withFile(dir, name string, fn func(io.Reader) error) error {
	f, err := os.Open(filepath.Join(dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open snapshot file: %w", err)
	}
	defer f.Close()
	if err := fn(f); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func readJSON(dir, name string, v *Manifest) error {
	return withFile(dir, name, func(r io.Reader) error { return json.NewDecoder(r).Decode(v) })
}

func prefixAll(prefix string, ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = prefix + ": " + s
	}
	return out
}
