package translate

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestSQLFilterReadsEqualityOnText(t *testing.T) {
	type alts = []map[string]string
	for expr, want := range map[string]alts{
		"Area = 'north'":                               {{"Area": "north"}},
		"Area='north'":                                 {{"Area": "north"}},
		"'north' = Area":                               {{"Area": "north"}},
		"user.Area = 'north'":                          {{"Area": "north"}},
		"USER.[Area code] = 'n'":                       {{"Area code": "n"}},
		"[a]]b] = 'x'":                                 {{"a]b": "x"}},
		`"Area" = 'north'`:                             {{"Area": "north"}},
		"Area = 'it''s'":                               {{"Area": "it's"}},
		"Area = 'north' and kind = 'order'":            {{"Area": "north", "kind": "order"}},
		"Area = 'north' AND\nkind = 'order'":           {{"Area": "north", "kind": "order"}},
		"Area = 'north' OR Area = 'south'":             {{"Area": "north"}, {"Area": "south"}},
		"Area IN ('north', 'south', 'north')":          {{"Area": "north"}, {"Area": "south"}},
		"a = '1' AND (b = '2' OR c = '3')":             {{"a": "1", "b": "2"}, {"a": "1", "c": "3"}},
		"a = '1' OR b = '2' AND c = '3'":               {{"a": "1"}, {"b": "2", "c": "3"}},
		"(a = '1' OR b = '2') AND c = '3'":             {{"a": "1", "c": "3"}, {"b": "2", "c": "3"}},
		"((a = '1'))":                                  {{"a": "1"}},
		"Area = 'north' AND area = 'north'":            {{"Area": "north"}},
		"Area = 'north' AND AREA = 'south'":            nil, // never true
		"Area IN ('a','b') AND Area = 'b'":             {{"Area": "b"}},
		"Area = 'AND' AND kind = 'x OR y'":             {{"Area": "AND", "kind": "x OR y"}},
		"Área = 'é'":                                   {{"Área": "é"}},
		"order_1 = 'x'":                                {{"order_1": "x"}},
		"Area IN ('a') OR kind IN ('b','c')":           {{"Area": "a"}, {"kind": "b"}, {"kind": "c"}},
		"a = '' ":                                      {{"a": ""}},
		"a IN ('x','y') AND b IN ('1','2')":            {{"a": "x", "b": "1"}, {"a": "x", "b": "2"}, {"a": "y", "b": "1"}, {"a": "y", "b": "2"}},
		"Area = 'north' AND (Area = 'south' OR k='v')": {{"Area": "north", "k": "v"}},
		"EXISTS(Area)":                                 {{"Area": sqlExists}},
		"exists ( [Area code] )":                       {{"Area code": sqlExists}},
		"EXISTS(user.Area) AND kind = 'x'":             {{"Area": sqlExists, "kind": "x"}},
		// Present and equal to something is equal to it, either way round.
		"EXISTS(Area) AND area = 'n'":     {{"Area": "n"}},
		"Area = 'n' AND EXISTS(AREA)":     {{"Area": "n"}},
		"EXISTS(a) AND EXISTS(A)":         {{"a": sqlExists}},
		"EXISTS(a) OR b = 'x'":            {{"a": sqlExists}, {"b": "x"}},
		"NOT EXISTS(Area)":                {{"Area": sqlAbsent}},
		"not exists(a) AND b = 'x'":       {{"a": sqlAbsent, "b": "x"}},
		"NOT EXISTS(a) AND NOT EXISTS(A)": {{"a": sqlAbsent}},
		// Absent, and present or equal to something: never.
		"NOT EXISTS(a) AND a = 'x'":               nil,
		"a = 'x' AND NOT EXISTS(a)":               nil,
		"EXISTS(a) AND NOT EXISTS(A)":             nil,
		"EXISTS(a) AND a = 'x' AND NOT EXISTS(b)": {{"a": "x", "b": sqlAbsent}},
		"paid = TRUE":                             {{"paid": sqlTrue}},
		"paid = false":                            {{"paid": sqlFalse}},
		"paid = true OR Area = 'n'":               {{"paid": sqlTrue}, {"Area": "n"}},
		"paid = TRUE AND paid = FALSE":            nil,
		"paid = TRUE AND PAID = true":             {{"paid": sqlTrue}},
		// The word in quotation marks is text, and not the boolean.
		"paid = 'true' AND paid = TRUE": nil,
	} {
		got, why := parseSQLFilter(expr)
		if why != "" || !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %v (%s), want %v", expr, got, why, want)
		}
	}
}

// Whatever says more than equality on text is refused, and the reason
// names what was met. Each of these would deliver more, or less, read as
// an equality.
func TestSQLFilterRefusesTheRest(t *testing.T) {
	for expr, part := range map[string]string{
		"amount > 1000":                "uses >",
		"amount = 1000":                "a number",
		"Area <> 'north'":              "uses <>",
		"Area != 'north'":              "uses !=",
		"NOT Area = 'north'":           "uses NOT",
		"not (Area = 'north')":         "uses NOT",
		"Area = 'north' AND NOT b='c'": "uses NOT",
		"EXISTS Area":                  "EXISTS is not followed",
		"EXISTS(Area, kind)":           "EXISTS takes one property",
		"EXISTS('x')":                  "where a property's name is expected",
		"EXISTS(sys.Label)":            "system property sys.Label",
		"paid = TRUE = 'x'":            "not expected",
		"TRUE = paid":                  "uses TRUE",
		"paid IN (TRUE)":               "the list after paid IN",
		"NOT EXISTS Area":              "EXISTS is not followed",
		"NOT (EXISTS(Area))":           "uses NOT",
		"NOT NOT EXISTS(Area)":         "uses NOT",
		"Area IS NULL":                 "uses IS after Area",
		"Area IS NOT NULL":             "uses IS after Area",
		"Area LIKE 'n%'":               "uses LIKE after Area",
		"Area NOT IN ('a')":            "uses NOT after Area",
		"Area NOT LIKE 'a'":            "uses NOT after Area",
		"TRUE":                         "uses TRUE",
		"Area = kind":                  "compares Area with kind",
		"Area = NULL":                  "compares Area with NULL",
		"sys.Label = 'x'":              "system property sys.Label",
		"SYS.To = 'x'":                 "system property sys.To",
		"app.Area = 'x'":               "not a scope",
		"property('Area') = 'x'":       "calls property()",
		"p(Area) = 'x'":                "calls p()",
		"newid() = 'x'":                "calls newid()",
		"Area = 'north":                "not closed",
		"[Area = 'north'":              "not closed",
		"(Area = 'north'":              "bracket is not closed",
		"Area = 'north')":              "not expected",
		"Area = 'north' kind = 'x'":    "not expected",
		"Area = 'north' AND":           "its end",
		"Area":                         "its end after Area",
		"":                             "its end",
		"Area IN ()":                   "the list after Area IN",
		"Area IN ('a', 5)":             "a number",
		"Area IN ('a' 'b')":            "not closed",
		"Area IN 'a'":                  "not followed by a list",
		"Area + 'x' = 'northx'":        "uses +",
		"Area = 'a' + 'b'":             "uses +",
		"-Area = 'x'":                  "uses -",
		"Area = 'x'; DROP":             "uses ;",
		"user. = 'x'":                  "not followed by a property",
		"'a' = 'a'":                    "where a property's name is expected",
		"'north' IN (Area)":            "after a text value",
		"1=1 AND Area = 'x'":           "a number",
	} {
		got, why := parseSQLFilter(expr)
		if why == "" || got != nil || !strings.Contains(why, part) {
			t.Errorf("%q: %v, %q; want a refusal that says %q", expr, got, why, part)
		}
	}
	// More alternatives than a target takes, by OR and by AND.
	var ors, a, b []string
	for i := 0; i <= sqlFilterMax; i++ {
		ors = append(ors, fmt.Sprintf("a = '%d'", i))
	}
	for i := 0; i < 13; i++ {
		a, b = append(a, fmt.Sprintf("'%d'", i)), append(b, fmt.Sprintf("'%d'", i))
	}
	for _, expr := range []string{strings.Join(ors, " OR "), "a IN (" + strings.Join(a, ",") + ") AND b IN (" + strings.Join(b, ",") + ")"} {
		if _, why := parseSQLFilter(expr); !strings.Contains(why, "more than 150 alternatives") {
			t.Errorf("a filter of too many alternatives: %q", why)
		}
	}
}

// The filter is carried by each destination as that destination says it,
// with the one thing none keeps named.
func TestSQLFilterIsCarriedByEveryDestination(t *testing.T) {
	for name, m := range maps() {
		r := run(t, m)
		for _, sub := range []string{"north", "urgent"} {
			e := entry(t, r, "Microsoft.ServiceBus/namespaces/topics/subscriptions rg/shop/events/"+sub)
			if e.State != WithLosses {
				t.Fatalf("%s %s: %s %s", name, sub, e.State, e.Reason)
			}
			var said []string
			for _, l := range e.Losses {
				if l.Field == "properties.sqlFilter.sqlExpression" {
					if l.Widens || l.Unread {
						t.Errorf("%s %s: the name's case is a loss, not a widening", name, sub)
					}
					said = append(said, l.Why[strings.LastIndex(l.Why, ": ")+2:])
				}
			}
			want := map[string]string{"north": "Area", "urgent": "Area, kind"}[sub]
			if len(said) != 1 || said[0] != want {
				t.Errorf("%s %s: names said %q, want %q once", name, sub, said, want)
			}
		}
		// "area" in a second rule is the first rule's "Area".
		var texts []string
		for _, snap := range r.Snapshots {
			for _, obj := range snap.Objects {
				texts = append(texts, fmt.Sprint(obj.Body))
			}
		}
		all := strings.Join(texts, "\n")
		if strings.Contains(all, "area:") || strings.Contains(all, "attributes.area") {
			t.Errorf("%s: a property is written in two spellings", name)
		}
		for _, v := range []string{"coast", "isle", "north", "it's late"} {
			if !strings.Contains(all, v) {
				t.Errorf("%s: no filter matches %q", name, v)
			}
		}
		// What is still refused is refused with what was met.
		if e := entry(t, r, "Microsoft.ServiceBus/namespaces/topics/subscriptions rg/shop/events/fraud"); e.State != Refused || !strings.Contains(e.Reason, "it uses >") {
			t.Errorf("%s: fraud: %s %s", name, e.State, e.Reason)
		}
	}
}

func TestSNSFilterLimits(t *testing.T) {
	six := map[string]string{}
	for _, k := range []string{"a", "b", "c", "d", "e", "f"} {
		six[k] = "x"
	}
	many := make([]map[string]string, 151)
	for i := range many {
		many[i] = map[string]string{"a": fmt.Sprint(i)}
	}
	for part, rules := range map[string][]map[string]string{
		"five keys":        {six},
		"150 combinations": many,
		`"Area code"`:      {{"Area code": "x"}},
		`"AWS.x"`:          {{"AWS.x": "x"}},
		`"a..b"`:           {{"a..b": "x"}},
		`".a"`:             {{".a": "x"}},
	} {
		if why := snsFilterLimits(rules); !strings.Contains(why, part) {
			t.Errorf("%v: %q, want %q", len(rules), why, part)
		}
	}
	five := []map[string]string{{"a": "1", "b": "1"}, {"c": "1", "d.e": "1", "f-g_h": "1"}}
	if why := snsFilterLimits(five); why != "" {
		t.Errorf("five keys refused: %s", why)
	}
	// One property in every rule is one key with the values, in order.
	got := snsFilter([]map[string]string{{"a": "z"}, {"a": "b"}, {"a": "z"}})
	if want := map[string]any{"a": []any{"b", "z"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("%v, want %v", got, want)
	}
	or := snsFilter([]map[string]string{{"a": "1"}, {"b": "2"}})
	keys := make([]string, 0)
	for k := range or {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) != 1 || keys[0] != "$or" {
		t.Errorf("two properties: %v", or)
	}
}

// A filter SNS would not take refuses the subscription; Pub/Sub, which
// has no limit on keys, carries it.
func TestSQLFilterOverSNSLimitsIsRefused(t *testing.T) {
	s := fixture()
	s.Objects = append(s.Objects,
		az("Microsoft.ServiceBus/namespaces/topics/subscriptions", "rg", "shop/events/wide", pr(map[string]any{
			"lockDuration": "PT1M", "maxDeliveryCount": 10, "status": "Active"})),
		az("Microsoft.ServiceBus/namespaces/topics/subscriptions/rules", "rg", "shop/events/wide/six", pr(map[string]any{
			"filterType": "SqlFilter", "sqlFilter": map[string]any{"sqlExpression": "a='1' AND b='1' AND c='1' AND d='1' AND e='1' AND f='1'"}})))
	for name, want := range map[string]State{"sqs-sns": Refused, "pubsub": WithLosses} {
		r, err := translateFixture(t, s, maps()[name])
		if err != nil {
			t.Fatal(err)
		}
		e := entry(t, r, "Microsoft.ServiceBus/namespaces/topics/subscriptions rg/shop/events/wide")
		if e.State != want || (want == Refused && !strings.Contains(e.Reason, "five keys")) {
			t.Errorf("%s: %s %q", name, e.State, e.Reason)
		}
	}
}

// EXISTS is carried where the destination can ask whether an attribute
// is there, and refused where it cannot. A comparison with a boolean is
// carried only when the map says how a boolean is sent.
func TestSQLFilterExistsAndBooleans(t *testing.T) {
	s := fixture()
	sub := func(name, expr string) {
		s.Objects = append(s.Objects,
			az("Microsoft.ServiceBus/namespaces/topics/subscriptions", "rg", "shop/events/"+name, pr(map[string]any{
				"lockDuration": "PT1M", "maxDeliveryCount": 10, "status": "Active"})),
			az("Microsoft.ServiceBus/namespaces/topics/subscriptions/rules", "rg", "shop/events/"+name+"/r", pr(map[string]any{
				"filterType": "SqlFilter", "sqlFilter": map[string]any{"sqlExpression": expr}})))
	}
	sub("has", "EXISTS(Trace) OR Area = 'north'")
	sub("hasnot", "Area = 'north' AND NOT EXISTS(Trace)")
	sub("paid", "Paid = TRUE AND Late = false")
	const has, paid = "Microsoft.ServiceBus/namespaces/topics/subscriptions rg/shop/events/has", "Microsoft.ServiceBus/namespaces/topics/subscriptions rg/shop/events/paid"
	text := func(r Result) string {
		var b []string
		for _, snap := range r.Snapshots {
			for _, obj := range snap.Objects {
				b = append(b, canonJSON(obj.Body))
			}
		}
		return strings.Join(b, "\n")
	}
	for name, m := range maps() {
		r, err := translateFixture(t, s, m)
		if err != nil {
			t.Fatal(err)
		}
		// Without the map's word, a boolean is refused, with the key.
		if e := entry(t, r, paid); e.State != Refused || !strings.Contains(e.Reason, "booleans: text") || !strings.Contains(e.Reason, "with a boolean") {
			t.Errorf("%s: a boolean with no word from the map: %s %q", name, e.State, e.Reason)
		}
		e := entry(t, r, has)
		all := text(r)
		switch name {
		case "sqs-sns":
			if e.State != WithLosses || !strings.Contains(all, `"Trace":[{"exists":true}]`) {
				t.Errorf("sqs-sns: EXISTS: %s %q", e.State, e.Reason)
			}
		case "pubsub":
			if e.State != WithLosses || !strings.Contains(all, `(attributes.Area = \"north\") OR (attributes:Trace)`) {
				t.Errorf("pubsub: EXISTS: %s %q", e.State, e.Reason)
			}
		case "rabbitmq":
			if e.State != Refused || !strings.Contains(e.Reason, "property Trace is present") {
				t.Errorf("rabbitmq: EXISTS: %s %q", e.State, e.Reason)
			}
		default:
			t.Fatalf("a destination this test does not know: %s", name)
		}
		hn := entry(t, r, strings.Replace(has, "/has", "/hasnot", 1))
		wantNot := map[string]string{"sqs-sns": `"Trace":[{"exists":false}]`, "pubsub": `NOT attributes:Trace`}[name]
		if name == "rabbitmq" {
			if hn.State != Refused || !strings.Contains(hn.Reason, "or when it is absent") {
				t.Errorf("rabbitmq: NOT EXISTS: %s %q", hn.State, hn.Reason)
			}
		} else if hn.State != WithLosses || !strings.Contains(all, wantNot) {
			t.Errorf("%s: NOT EXISTS: %s %q, want %s", name, hn.State, hn.Reason, wantNot)
		}
		if strings.Contains(all, `\u0000`) {
			t.Errorf("%s: a marker was written as a value", name)
		}
		// With it, the words true and false, and the loss says so.
		m.Booleans = "text"
		r, err = translateFixture(t, s, m)
		if err != nil {
			t.Fatal(err)
		}
		e = entry(t, r, paid)
		if e.State != WithLosses {
			t.Fatalf("%s: booleans: text: %s %q", name, e.State, e.Reason)
		}
		said := false
		for _, l := range e.Losses {
			said = said || (strings.Contains(l.Why, "word true or false") && strings.HasSuffix(l.Why, ": Late, Paid") && !l.Widens)
		}
		all = text(r)
		want := map[string][]string{
			"sqs-sns":  {`"Late":["false"]`, `"Paid":["true"]`},
			"pubsub":   {`attributes.Late = \"false\" AND attributes.Paid = \"true\"`},
			"rabbitmq": {`"Late":"false"`, `"Paid":"true"`},
		}[name]
		for _, w := range want {
			if !strings.Contains(all, w) {
				t.Errorf("%s: booleans as text: no %s", name, w)
			}
		}
		if !said || len(want) == 0 || strings.Contains(all, `\u0000`) {
			t.Errorf("%s: booleans as text: said %v: %+v", name, said, e.Losses)
		}
	}
	m := maps()["sqs-sns"]
	m.Booleans = "number"
	if err := m.validate(); err == nil || !strings.Contains(err.Error(), "booleans") {
		t.Errorf("a way to send a boolean nobody knows: %v", err)
	}
}
