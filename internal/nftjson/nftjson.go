// Package nftjson compiles `nft -j list ruleset` output (libnftables-json(5))
// into the rule IR.
//
// Statements and expressions in that format are one-key objects whose key
// names the type. They are decoded into json.RawMessage only long enough to
// read the key, then into concrete structs.
package nftjson

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Santaniel0/fwreach/internal/netpkt"
	"github.com/Santaniel0/fwreach/internal/ruleset"
)

// ErrFormat is returned for JSON that does not follow the nft schema.
var ErrFormat = errors.New("not nft JSON ruleset output")

// Result is a parsed ruleset.
type Result struct {
	Tables   []*ruleset.Table
	Warnings []string
}

type document struct {
	Nftables []struct {
		Table *struct{ Family, Name string } `json:"table"`
		Chain *chainJSON                     `json:"chain"`
		Rule  *ruleJSON                      `json:"rule"`
		Set   *setJSON                       `json:"set"`
		Map   *setJSON                       `json:"map"`
	} `json:"nftables"`
}

type chainJSON struct {
	Family, Table, Name, Type, Hook, Policy string
	Prio                                    *int `json:"prio"`
}

type ruleJSON struct {
	Family, Table, Chain, Comment string
	Expr                          []json.RawMessage `json:"expr"`
}

type setJSON struct {
	Family, Table, Name string
	Elem                []json.RawMessage `json:"elem"`
}

type matchJSON struct {
	Op    string          `json:"op"`
	Left  json.RawMessage `json:"left"`
	Right json.RawMessage `json:"right"`
}

type exprJSON struct {
	Payload *struct{ Protocol, Field string } `json:"payload"`
	Meta    *struct{ Key string }             `json:"meta"`
	Ct      *struct{ Key, Dir string }        `json:"ct"`
	Fib     *struct {
		Result string   `json:"result"`
		Flags  []string `json:"flags"`
	} `json:"fib"`
	And []json.RawMessage `json:"&"`
}

type parser struct {
	sets  map[string][]json.RawMessage
	warns []string
}

// Parse reads a whole `nft -j list ruleset` document.
func Parse(r io.Reader) (*Result, error) {
	var doc document
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFormat, err)
	}
	if doc.Nftables == nil {
		return nil, fmt.Errorf("%w: no \"nftables\" array", ErrFormat)
	}
	p := &parser{sets: map[string][]json.RawMessage{}}
	tables := map[string]*ruleset.Table{}
	res := &Result{}
	// Rules go in a second pass: they can refer to sets and chains that
	// appear later in the array.
	for _, e := range doc.Nftables {
		switch {
		case e.Table != nil:
			fam, ok := family(e.Table.Family)
			if !ok {
				res.Warnings = append(res.Warnings, fmt.Sprintf("table %s %s skipped: family not modeled", e.Table.Family, e.Table.Name))
				continue
			}
			t := &ruleset.Table{Family: fam, Name: e.Table.Name, Source: ruleset.SourceNftables}
			tables[e.Table.Family+" "+e.Table.Name] = t
			res.Tables = append(res.Tables, t)
		case e.Set != nil || e.Map != nil:
			s := e.Set
			if s == nil {
				s = e.Map
			}
			p.sets[s.Family+" "+s.Table+" "+s.Name] = s.Elem
		case e.Chain != nil:
			t := tables[e.Chain.Family+" "+e.Chain.Table]
			if t == nil {
				continue
			}
			c, err := chain(e.Chain)
			if err != nil {
				return nil, err
			}
			t.Chains = append(t.Chains, c)
		}
	}
	pos := map[*ruleset.Chain]int{}
	for _, e := range doc.Nftables {
		if e.Rule != nil {
			t := tables[e.Rule.Family+" "+e.Rule.Table]
			if t == nil {
				continue
			}
			c := t.Chain(e.Rule.Chain)
			if c == nil {
				return nil, fmt.Errorf("%w: rule for unknown chain %s", ErrFormat, e.Rule.Chain)
			}
			rules, err := p.rule(e.Rule, t)
			if err != nil {
				return nil, fmt.Errorf("%s %s: %w", t.ID(), c.Name, err)
			}
			pos[c]++
			for _, r := range rules {
				r.Pos = pos[c]
				c.Rules = append(c.Rules, r)
			}
		}
	}
	res.Warnings = append(res.Warnings, p.warns...)
	return res, nil
}

func family(s string) (ruleset.TableFamily, bool) {
	switch s {
	case "ip":
		return ruleset.FamilyIP, true
	case "ip6":
		return ruleset.FamilyIP6, true
	case "inet":
		return ruleset.FamilyInet, true
	}
	return 0, false
}

func chain(cj *chainJSON) (*ruleset.Chain, error) {
	c := &ruleset.Chain{Name: cj.Name}
	if cj.Hook == "" {
		return c, nil
	}
	hook, ok := netpkt.ParseHook(cj.Hook)
	if !ok {
		return c, nil // ingress and egress hooks are not modeled
	}
	b := &ruleset.BaseChain{Hook: hook, Kind: ruleset.KindFilter, Policy: ruleset.Accept}
	switch cj.Type {
	case "filter":
	case "nat":
		b.Kind = ruleset.KindNAT
	case "route":
		b.Kind = ruleset.KindRoute
	default:
		return nil, fmt.Errorf("%w: chain %s type %q", ErrFormat, cj.Name, cj.Type)
	}
	if cj.Prio != nil {
		b.Priority = *cj.Prio
	}
	if cj.Policy == "drop" {
		b.Policy = ruleset.Drop
	}
	c.Base = b
	return c, nil
}

// rule compiles one rule. A verdict map turns into one IR rule per map
// element: keys are disjoint, so trying them in turn is the same lookup.
func (p *parser) rule(rj *ruleJSON, t *ruleset.Table) ([]ruleset.Rule, error) {
	r := ruleset.Rule{Action: ruleset.Action{Kind: ruleset.ActContinue}}
	var text []string
	for _, raw := range rj.Expr {
		key, val, err := oneKey(raw)
		if err != nil {
			return nil, err
		}
		switch key {
		case "match":
			var m matchJSON
			if err := json.Unmarshal(val, &m); err != nil {
				return nil, fmt.Errorf("%w: match: %w", ErrFormat, err)
			}
			s, ms := p.match(m, rj)
			text = append(text, s)
			r.Matches = append(r.Matches, ms...)
		case "vmap":
			var v struct{ Key, Data json.RawMessage }
			if err := json.Unmarshal(val, &v); err != nil {
				return nil, fmt.Errorf("%w: vmap: %w", ErrFormat, err)
			}
			return p.vmap(r, strings.Join(text, " "), v.Key, v.Data, rj)
		case "counter", "log", "notrack", "masquerade", "snat", "quota":
			text = append(text, key)
		case "limit":
			text = append(text, "limit")
			r.Matches = append(r.Matches, ruleset.UnknownMatch{What: "limit"})
		case "xt":
			// iptables-nft compat expressions: JSON keeps only the name.
			var x struct{ Type, Name string }
			_ = json.Unmarshal(val, &x)
			text = append(text, "xt "+x.Type+" "+x.Name)
			if x.Type == "target" {
				r.Action = ruleset.Action{Kind: ruleset.ActUnknown, What: "xt target " + x.Name}
			} else {
				r.Matches = append(r.Matches, ruleset.UnknownMatch{What: "xt match " + x.Name})
			}
		default:
			a, s, err := action(key, val)
			if err != nil {
				return nil, err
			}
			r.Action = a
			text = append(text, s)
		}
	}
	if rj.Comment != "" {
		text = append(text, "comment "+strconv.Quote(rj.Comment))
	}
	r.Text = strings.Join(text, " ")
	return []ruleset.Rule{r}, nil
}

func (p *parser) vmap(base ruleset.Rule, prefix string, key, data json.RawMessage, rj *ruleJSON) ([]ruleset.Rule, error) {
	keyText := render(key)
	var elems []json.RawMessage
	var name string
	if err := json.Unmarshal(data, &name); err == nil && strings.HasPrefix(name, "@") {
		elems = p.sets[rj.Family+" "+rj.Table+" "+name[1:]]
	} else {
		var inline struct{ Set []json.RawMessage }
		if err := json.Unmarshal(data, &inline); err != nil {
			return nil, fmt.Errorf("%w: vmap data", ErrFormat)
		}
		elems, name = inline.Set, "{...}"
	}
	var out []ruleset.Rule
	for _, e := range elems {
		var pair []json.RawMessage
		if err := json.Unmarshal(e, &pair); err != nil || len(pair) != 2 {
			return nil, fmt.Errorf("%w: vmap element %s", ErrFormat, e)
		}
		vkey, vval, err := oneKey(pair[1])
		if err != nil {
			return nil, err
		}
		a, as, err := action(vkey, vval)
		if err != nil {
			return nil, err
		}
		s, ms := p.match(matchJSON{Op: "==", Left: key, Right: pair[0]}, rj)
		r := base
		r.Matches = append(append([]ruleset.Match(nil), base.Matches...), ms...)
		r.Action = a
		r.Text = strings.TrimSpace(prefix + " " + keyText + " vmap " + name + " (" + strings.TrimPrefix(s, keyText+" ") + " : " + as + ")")
		out = append(out, r)
	}
	return out, nil
}

func oneKey(raw json.RawMessage) (string, json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || len(m) != 1 {
		return "", nil, fmt.Errorf("%w: expected a one-key object, got %s", ErrFormat, raw)
	}
	for k, v := range m {
		return k, v, nil
	}
	return "", nil, fmt.Errorf("%w: empty object", ErrFormat)
}

func action(key string, val json.RawMessage) (ruleset.Action, string, error) {
	switch key {
	case "accept":
		return ruleset.Action{Kind: ruleset.ActVerdict, Verdict: ruleset.Accept}, key, nil
	case "drop":
		return ruleset.Action{Kind: ruleset.ActVerdict, Verdict: ruleset.Drop}, key, nil
	case "reject":
		return ruleset.Action{Kind: ruleset.ActVerdict, Verdict: ruleset.Reject}, key, nil
	case "return":
		return ruleset.Action{Kind: ruleset.ActReturn}, key, nil
	case "continue":
		return ruleset.Action{Kind: ruleset.ActContinue}, key, nil
	case "jump", "goto":
		var j struct{ Target string }
		if err := json.Unmarshal(val, &j); err != nil || j.Target == "" {
			return ruleset.Action{}, "", fmt.Errorf("%w: %s without target", ErrFormat, key)
		}
		kind := ruleset.ActJump
		if key == "goto" {
			kind = ruleset.ActGoto
		}
		return ruleset.Action{Kind: kind, Target: j.Target}, key + " " + j.Target, nil
	case "dnat", "redirect":
		var d struct {
			Addr string `json:"addr"`
			Port uint16 `json:"port"`
		}
		if err := json.Unmarshal(val, &d); err != nil {
			return ruleset.Action{Kind: ruleset.ActUnknown, What: key + " with an expression target"}, key + " to <expr>", nil
		}
		a := ruleset.Action{Kind: ruleset.ActDNAT, DNATPort: d.Port, What: key}
		text := key + " to " + d.Addr
		if key == "redirect" {
			a.Kind, text = ruleset.ActRedirect, "redirect to"
		} else if addr, err := netip.ParseAddr(d.Addr); err == nil {
			a.DNATAddr = addr
		} else {
			return ruleset.Action{Kind: ruleset.ActUnknown, What: "dnat to " + d.Addr}, text, nil
		}
		if d.Port != 0 {
			text += ":" + strconv.Itoa(int(d.Port))
		}
		return a, text, nil
	case "mangle":
		var m struct{ Key, Value json.RawMessage }
		if err := json.Unmarshal(val, &m); err != nil || render(m.Key) != "meta mark" {
			return ruleset.Action{Kind: ruleset.ActContinue, What: "mangle"}, "mangle " + render(m.Key), nil
		}
		var mark uint32
		if err := json.Unmarshal(m.Value, &mark); err != nil {
			return ruleset.Action{Kind: ruleset.ActUnknown, What: "meta mark set <expr>"}, "meta mark set <expr>", nil
		}
		return ruleset.Action{Kind: ruleset.ActSetMark, Mark: mark, MarkMask: 0xffffffff}, "meta mark set " + strconv.Itoa(int(mark)), nil
	}
	return ruleset.Action{Kind: ruleset.ActUnknown, What: key}, key, nil
}
