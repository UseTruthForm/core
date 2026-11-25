package translate

import (
	"encoding/json"
	"fmt"
	"sort"
)

// props reads one object's settings and keeps count of what was read, so
// that a setting no rule names becomes a loss rather than disappearing.
type props struct {
	m      map[string]any
	used   map[string]bool
	losses []Loss
	prefix string
}

func newProps(m map[string]any, prefix string) *props {
	if m == nil {
		m = map[string]any{}
	}
	return &props{m: m, used: map[string]bool{}, prefix: prefix}
}

func (p *props) has(k string) bool { _, ok := p.m[k]; return ok }

func (p *props) take(k string) (any, bool) {
	v, ok := p.m[k]
	p.used[k] = true
	return v, ok
}

func (p *props) str(k string) string {
	v, _ := p.take(k)
	s, _ := v.(string)
	return s
}

func (p *props) boolean(k string) bool {
	v, _ := p.take(k)
	b, _ := v.(bool)
	return b
}

func (p *props) integer(k string) *int {
	v, ok := p.take(k)
	if !ok || v == nil {
		return nil
	}
	switch n := v.(type) {
	case float64:
		i := int(n)
		return &i
	case int:
		return &n
	case int64:
		i := int(n)
		return &i
	case json.Number:
		i, err := n.Int64()
		if err == nil {
			j := int(i)
			return &j
		}
	}
	p.lose(k, fmt.Sprintf("%v is not a whole number", v), false)
	return nil
}

// duration reads an ISO 8601 duration as seconds; nil when unset or
// Service Bus's "never".
func (p *props) duration(k string) *float64 {
	s := p.str(k)
	if s == "" {
		return nil
	}
	sec, err := seconds(s)
	if err != nil {
		p.lose(k, err.Error(), false)
		return nil
	}
	if sec >= unbounded {
		return nil
	}
	return &sec
}

// quiet reads settings that carry nothing to translate: the server's own
// figures, should a capture have kept them, and performance hints.
func (p *props) quiet(ks ...string) {
	for _, k := range ks {
		p.used[k] = true
	}
}

// unlessDefault reads a setting that has no equivalent anywhere, and is a
// loss only when it is not the source's default.
func (p *props) unlessDefault(k string, def any, why string) {
	v, ok := p.take(k)
	if !ok || v == nil || fmt.Sprint(v) == fmt.Sprint(def) {
		return
	}
	p.lose(k, fmt.Sprintf("%v: %s", v, why), false)
}

func (p *props) lose(k, why string, widens bool) {
	p.losses = append(p.losses, Loss{Field: p.prefix + k, Why: why, Widens: widens})
}

// rest names, as losses, the settings no rule read.
func (p *props) rest() []Loss {
	var ks []string
	for k := range p.m {
		if !p.used[k] {
			ks = append(ks, k)
		}
	}
	sort.Strings(ks)
	out := append([]Loss(nil), p.losses...)
	for _, k := range ks {
		out = append(out, Loss{Field: p.prefix + k, Why: "no rule reads this setting yet: it is not carried over", Unread: true})
	}
	return out
}
