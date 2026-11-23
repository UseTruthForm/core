package translate

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// A Service Bus SQL filter, for the part of the language that says no more
// than a correlation filter does: text values compared for equality, joined
// with AND, OR and IN. That is what an SNS filter policy, a Pub/Sub filter
// and a RabbitMQ headers binding can each say exactly, and nearly all of
// what filters in use say. EXISTS and NOT EXISTS are read too, for the destinations that
// can ask whether an attribute is there, and a comparison with TRUE or
// FALSE, when the map says how a boolean is sent (booleans). Everything
// else (NOT, LIKE, IS NULL, <>, ordering, arithmetic, numbers, system
// properties, functions) is refused with what was met: a filter half-carried delivers
// more than the source did, or less, and nobody chose either.
//
// The grammar and its meaning are Microsoft's:
// https://learn.microsoft.com/azure/service-bus-messaging/service-bus-messaging-sql-filter
//   - a property with no scope is a user (application) property;
//   - a user property a message does not carry is "unknown", and a rule
//     delivers only when its filter is true: with no NOT in what is read
//     here, a missing property simply fails its comparison, as a missing
//     attribute does on each target;
//   - "Property names are case-insensitive", which no target is: see
//     sqlFilterCaseLoss.

// sqlFilterMax bounds the alternatives one filter is expanded to. SNS
// takes a filter policy of at most 150 combinations
// (https://docs.aws.amazon.com/sns/latest/dg/subscription-filter-policy-constraints.html).
const sqlFilterMax = 150

// What a property is asked to be, beside a text value: only present, or
// the boolean true or false. No text value starts with a NUL, so these
// stand in the place of one.
const (
	sqlExists = "\x00exists"
	sqlAbsent = "\x00absent" // NOT EXISTS
	sqlTrue   = "\x00true"
	sqlFalse  = "\x00false"
)

type sqlTok struct {
	kind string // id, str, op, end
	text string
}

// sqlLex splits an expression. It returns why it cannot.
func sqlLex(s string) ([]sqlTok, string) {
	var out []sqlTok
	rs := []rune(s)
	// quoted reads to the closing mark, which doubled stands for itself.
	quoted := func(i int, closer rune) (string, int, bool) {
		var b strings.Builder
		for i < len(rs) {
			if rs[i] == closer {
				if i+1 < len(rs) && rs[i+1] == closer {
					b.WriteRune(closer)
					i += 2
					continue
				}
				return b.String(), i + 1, true
			}
			b.WriteRune(rs[i])
			i++
		}
		return "", i, false
	}
	for i := 0; i < len(rs); {
		c := rs[i]
		switch {
		case unicode.IsSpace(c):
			i++
		case c == '\'':
			v, n, ok := quoted(i+1, '\'')
			if !ok {
				return nil, "a text value is not closed"
			}
			out, i = append(out, sqlTok{"str", v}), n
		case c == '[' || c == '"':
			closer := map[rune]rune{'[': ']', '"': '"'}[c]
			v, n, ok := quoted(i+1, closer)
			if !ok || v == "" {
				return nil, "a property name in brackets or quotation marks is not closed"
			}
			out, i = append(out, sqlTok{"name", v}), n
		case unicode.IsLetter(c):
			j := i
			for j < len(rs) && (unicode.IsLetter(rs[j]) || unicode.IsDigit(rs[j]) || rs[j] == '_') {
				j++
			}
			out, i = append(out, sqlTok{"id", string(rs[i:j])}), j
		case unicode.IsDigit(c):
			return nil, "it compares with a number, and only text values are translated"
		case c == '(' || c == ')' || c == ',' || c == '=' || c == '.':
			out, i = append(out, sqlTok{"op", string(c)}), i+1
		default:
			j := i
			for j < len(rs) && strings.ContainsRune("<>!=+-*/%", rs[j]) {
				j++
			}
			if j == i {
				j = i + 1
			}
			return nil, fmt.Sprintf("it uses %s, and only =, IN, AND and OR are translated", string(rs[i:j]))
		}
	}
	return append(out, sqlTok{"end", ""}), ""
}

type sqlParser struct {
	toks []sqlTok
	pos  int
	why  string
}

func (p *sqlParser) peek() sqlTok { return p.toks[p.pos] }

func (p *sqlParser) fail(why string, a ...any) []map[string]string {
	if p.why == "" {
		p.why = fmt.Sprintf(why, a...)
	}
	return nil
}

// word reports whether the next token is that keyword, and takes it.
func (p *sqlParser) word(w string) bool {
	if t := p.peek(); t.kind == "id" && strings.EqualFold(t.text, w) {
		p.pos++
		return true
	}
	return false
}

func (p *sqlParser) op(o string) bool {
	if t := p.peek(); t.kind == "op" && t.text == o {
		p.pos++
		return true
	}
	return false
}

// parseSQLFilter reads a filter as alternatives, any of which delivers,
// each a set of properties that must all equal their value. No
// alternatives and no why means the filter is never true.
func parseSQLFilter(expr string) ([]map[string]string, string) {
	toks, why := sqlLex(expr)
	if why != "" {
		return nil, why
	}
	p := &sqlParser{toks: toks}
	alts := p.or()
	if p.why == "" && p.peek().kind != "end" {
		p.fail("%s is not expected where it stands", p.show(p.peek()))
	}
	if p.why != "" {
		return nil, p.why
	}
	return alts, ""
}

func (p *sqlParser) show(t sqlTok) string {
	switch t.kind {
	case "end":
		return "its end"
	case "str":
		return "'" + t.text + "'"
	}
	return t.text
}

func (p *sqlParser) or() []map[string]string {
	alts := p.and()
	for p.why == "" && p.word("OR") {
		alts = append(alts, p.and()...)
		if len(alts) > sqlFilterMax {
			return p.fail("it expands to more than %d alternatives", sqlFilterMax)
		}
	}
	return alts
}

func (p *sqlParser) and() []map[string]string {
	alts := p.term()
	for p.why == "" && p.word("AND") {
		right := p.term()
		if len(alts)*len(right) > sqlFilterMax {
			return p.fail("it expands to more than %d alternatives", sqlFilterMax)
		}
		var both []map[string]string
		for _, a := range alts {
			for _, b := range right {
				if m, ok := sqlBoth(a, b); ok {
					both = append(both, m)
				}
			}
		}
		alts = both
	}
	return alts
}

// sqlBoth is the alternative that needs all of a and all of b, or false
// when they ask one property to equal two values, which no message does.
// A property is one whatever its letters' case, as Service Bus reads it.
func sqlBoth(a, b map[string]string) (map[string]string, bool) {
	m := map[string]string{}
	for k, v := range a {
		m[k] = v
	}
	for k, v := range b {
		same := k
		for have := range m {
			if strings.EqualFold(have, k) {
				same = have
			}
		}
		old, ok := m[same]
		switch {
		case ok && (old == sqlAbsent) != (v == sqlAbsent):
			// Absent, and present or equal to something: never.
			return nil, false
		case ok && v == sqlExists:
			// Present and equal to something is equal to it.
			continue
		case ok && old != sqlExists && old != v:
			return nil, false
		}
		m[same] = v
	}
	return m, true
}

func (p *sqlParser) term() []map[string]string {
	if p.why != "" {
		return nil
	}
	t := p.peek()
	switch {
	case p.op("("):
		alts := p.or()
		if p.why == "" && !p.op(")") {
			return p.fail("a bracket is not closed")
		}
		return alts
	case t.kind == "str":
		// 'value' = Property
		p.pos++
		if !p.op("=") {
			return p.fail("it uses %s after a text value, and only = is translated", p.show(p.peek()))
		}
		name := p.property()
		if p.why != "" {
			return nil
		}
		return []map[string]string{{name: t.text}}
	case t.kind == "id" || t.kind == "name":
		if t.kind == "id" {
			// NOT EXISTS(property) is the one NOT read: EXISTS is never
			// unknown, so its NOT is simply that the property is absent.
			absent := false
			if strings.EqualFold(t.text, "NOT") && p.pos+1 < len(p.toks) && p.toks[p.pos+1].kind == "id" && strings.EqualFold(p.toks[p.pos+1].text, "EXISTS") {
				p.pos++
				t, absent = p.peek(), true
			}
			if strings.EqualFold(t.text, "EXISTS") {
				p.pos++
				if !p.op("(") {
					return p.fail("EXISTS is not followed by a property in brackets")
				}
				name := p.property()
				if p.why == "" && !p.op(")") {
					return p.fail("EXISTS takes one property")
				}
				if p.why != "" {
					return nil
				}
				if absent {
					return []map[string]string{{name: sqlAbsent}}
				}
				return []map[string]string{{name: sqlExists}}
			}
			for _, kw := range []string{"NOT", "TRUE", "FALSE", "NULL"} {
				if strings.EqualFold(t.text, kw) {
					return p.fail("it uses %s, and only =, IN, AND and OR on text values are translated", kw)
				}
			}
		}
		name := p.property()
		if p.why != "" {
			return nil
		}
		switch {
		case p.op("="):
			v := p.peek()
			if v.kind == "id" && (strings.EqualFold(v.text, "TRUE") || strings.EqualFold(v.text, "FALSE")) {
				p.pos++
				return []map[string]string{{name: map[bool]string{true: sqlTrue, false: sqlFalse}[strings.EqualFold(v.text, "TRUE")]}}
			}
			if v.kind != "str" {
				return p.fail("it compares %s with %s, and only a text value in single quotation marks is translated", name, p.show(v))
			}
			p.pos++
			return []map[string]string{{name: v.text}}
		case p.word("IN"):
			if !p.op("(") {
				return p.fail("IN is not followed by a list")
			}
			var alts []map[string]string
			seen := map[string]bool{}
			for {
				v := p.peek()
				if v.kind != "str" {
					return p.fail("the list after %s IN holds %s, and only text values are translated", name, p.show(v))
				}
				p.pos++
				if !seen[v.text] {
					seen[v.text] = true
					alts = append(alts, map[string]string{name: v.text})
				}
				if p.op(")") {
					return alts
				}
				if !p.op(",") {
					return p.fail("the list after %s IN is not closed", name)
				}
			}
		}
		return p.fail("it uses %s after %s, and only = and IN are translated", p.show(p.peek()), name)
	}
	return p.fail("%s is not expected where it stands", p.show(t))
}

// property reads a property's name: user scope, said or not. A system
// property is the message's own (its label, its session), which is not an
// attribute a target filters on.
func (p *sqlParser) property() string {
	t := p.peek()
	if t.kind != "id" && t.kind != "name" {
		p.fail("%s stands where a property's name is expected", p.show(t))
		return ""
	}
	p.pos++
	if t.kind == "id" && p.op(".") {
		n := p.peek()
		if n.kind != "id" && n.kind != "name" {
			p.fail("%s. is not followed by a property's name", t.text)
			return ""
		}
		p.pos++
		switch strings.ToLower(t.text) {
		case "user":
			return n.text
		case "sys":
			p.fail("it reads the system property sys.%s, which this destination cannot filter on", n.text)
		default:
			p.fail("%s is not a scope (user or sys)", t.text)
		}
		return ""
	}
	if p.peek().kind == "op" && p.peek().text == "(" && t.kind == "id" {
		p.fail("it calls %s(), and functions are not translated", t.text)
		return ""
	}
	return t.text
}

// sqlFilterCaseLoss names what no target keeps of a SQL filter: Service
// Bus matched a property whatever the case of its name's letters.
func sqlFilterCaseLoss(alts []map[string]string) Loss {
	seen := map[string]bool{}
	for _, m := range alts {
		for k := range m {
			seen[k] = true
		}
	}
	names := make([]string, 0, len(seen))
	for k := range seen {
		names = append(names, k)
	}
	sort.Strings(names)
	return Loss{Field: "properties.sqlFilter.sqlExpression",
		Why: "a SQL filter matched a property whatever the case of its name's letters; the target matches an attribute's name exactly, so a message is delivered only when its sender names it as the filter does: " + strings.Join(names, ", ")}
}
