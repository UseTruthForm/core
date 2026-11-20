package translate

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// The arithmetic of network rules: sets of IPv4 prefixes, and boxes of
// (protocol, destination ports, peer addresses) that a rule allows or
// denies. Translating an NSG is done with these, so that whether a
// rewritten rule set lets through anything the source did not is computed,
// not judged.

var anyV4 = netip.MustParsePrefix("0.0.0.0/0")

// prefixMinus is a with every address of b taken out, as prefixes.
func prefixMinus(a, b []netip.Prefix) []netip.Prefix {
	out := append([]netip.Prefix(nil), a...)
	for _, q := range b {
		var next []netip.Prefix
		for _, p := range out {
			next = append(next, minusOne(p, q)...)
		}
		out = next
	}
	return aggregate(out)
}

func minusOne(p, q netip.Prefix) []netip.Prefix {
	switch {
	case !p.Overlaps(q):
		return []netip.Prefix{p}
	case q.Bits() <= p.Bits(): // q holds p
		return nil
	}
	// p holds q: split p in two and keep going down the half that holds q.
	lo, hi := halves(p)
	return append(minusOne(lo, q), minusOne(hi, q)...)
}

func halves(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := p.Bits() + 1
	lo := netip.PrefixFrom(p.Addr(), bits).Masked()
	a := lo.Addr().As4()
	n := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	n |= 1 << (32 - bits)
	hi := netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}), bits)
	return lo, hi
}

// aggregate sorts prefixes, drops those another holds and joins halves.
func aggregate(ps []netip.Prefix) []netip.Prefix {
	set := map[netip.Prefix]bool{}
	for _, p := range ps {
		set[p.Masked()] = true
	}
	for changed := true; changed; {
		changed = false
		for p := range set {
			for q := range set {
				if p != q && q.Bits() < p.Bits() && q.Overlaps(p) {
					delete(set, p)
					changed = true
					break
				}
			}
		}
		for p := range set {
			if p.Bits() == 0 {
				continue
			}
			parent := netip.PrefixFrom(p.Addr(), p.Bits()-1).Masked()
			lo, hi := halves(parent)
			if set[lo] && set[hi] {
				delete(set, lo)
				delete(set, hi)
				set[parent] = true
				changed = true
				break
			}
		}
	}
	out := make([]netip.Prefix, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].Addr().Compare(out[j].Addr()); c != 0 {
			return c < 0
		}
		return out[i].Bits() < out[j].Bits()
	})
	return out
}

func prefixesOverlap(a, b []netip.Prefix) bool {
	for _, p := range a {
		for _, q := range b {
			if p.Overlaps(q) {
				return true
			}
		}
	}
	return false
}

// within reports whether every address of a is in b.
func within(a, b []netip.Prefix) bool { return len(prefixMinus(a, b)) == 0 }

func prefixStrings(ps []netip.Prefix) []any {
	out := make([]any, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

// box is a part of the traffic one direction of a rule set matches:
// a protocol, a destination port range (tcp and udp only) and the peer's
// addresses.
type box struct {
	proto  string // all, tcp, udp, icmp, esp, ah
	lo, hi int
	peer   []netip.Prefix
}

func (b box) ported() bool { return b.proto == "tcp" || b.proto == "udp" }

func (b box) String() string {
	ports := ""
	if b.ported() && !(b.lo == 0 && b.hi == 65535) {
		ports = "/" + portString(b.lo, b.hi)
	}
	ps := make([]string, len(b.peer))
	for i, p := range b.peer {
		ps[i] = p.String()
	}
	return b.proto + ports + " " + strings.Join(ps, ",")
}

func portString(lo, hi int) string {
	if lo == hi {
		return strconv.Itoa(lo)
	}
	return fmt.Sprintf("%d-%d", lo, hi)
}

func protoOverlap(a, b string) bool { return a == b || a == "all" || b == "all" }

func (b box) overlaps(d box) bool {
	return protoOverlap(b.proto, d.proto) && b.lo <= d.hi && d.lo <= b.hi && prefixesOverlap(b.peer, d.peer)
}

// namedProtos are the protocols a box of all protocols is split into when
// a deny takes one of them out: a security group cannot write "every
// protocol but TCP", so the rest (GRE, SCTP and the like) is lost.
var namedProtos = []string{"tcp", "udp", "icmp", "esp", "ah"}

// minus is b with what d matches taken out, as boxes. narrowed reports that
// protocols other than namedProtos were dropped to write it.
func (b box) minus(d box) (out []box, narrowed bool) {
	if !b.overlaps(d) {
		return []box{b}, false
	}
	if d.proto != "all" && b.proto == "all" {
		for _, p := range namedProtos {
			parts, _ := box{p, 0, 65535, b.peer}.minus(d)
			out = append(out, parts...)
		}
		return out, true
	}
	// The ports d does not match keep all of b's peers.
	if b.lo < d.lo {
		out = append(out, box{b.proto, b.lo, d.lo - 1, b.peer})
	}
	if d.hi < b.hi {
		out = append(out, box{b.proto, d.hi + 1, b.hi, b.peer})
	}
	// The ports both match keep the peers d does not.
	lo, hi := max(b.lo, d.lo), min(b.hi, d.hi)
	if rest := prefixMinus(b.peer, d.peer); len(rest) > 0 {
		out = append(out, box{b.proto, lo, hi, rest})
	}
	return out, false
}

// covers reports whether every packet b matches, a matches.
func (a box) covers(b box) bool {
	return (a.proto == "all" || a.proto == b.proto) && a.lo <= b.lo && b.hi <= a.hi && within(b.peer, a.peer)
}

// tidy makes a union of allowed boxes smaller without changing it: a box
// held by another goes, and a box's peers grow by what other boxes already
// allow for its traffic when that joins them into fewer prefixes.
func tidy(bs []box) []box {
	key := func(bs []box) string {
		var s []string
		for _, b := range bs {
			s = append(s, b.String())
		}
		return strings.Join(s, ";")
	}
	for {
		out := tidyOnce(bs)
		if key(out) == key(bs) {
			return out
		}
		bs = out
	}
}

func tidyOnce(bs []box) []box {
	var out []box
	for i, b := range bs {
		held := false
		for j, o := range bs {
			if i != j && o.covers(b) && !(b.covers(o) && j > i) {
				held = true
				break
			}
		}
		if !held {
			out = append(out, b)
		}
	}
	for i, b := range out {
		extra := append([]netip.Prefix(nil), b.peer...)
		for j, o := range out {
			if i != j && (o.proto == "all" || o.proto == b.proto) && o.lo <= b.lo && b.hi <= o.hi {
				extra = append(extra, o.peer...)
			}
		}
		if joined := aggregate(extra); len(joined) < len(b.peer) {
			out[i].peer = joined
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
