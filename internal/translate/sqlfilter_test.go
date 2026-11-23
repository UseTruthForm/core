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
		"EXISTS(Area)":                 "uses EXISTS",
		"Area IS NULL":                 "uses IS after Area",
		"Area IS NOT NULL":             "uses IS after Area",
		"Area LIKE 'n%'":               "uses LIKE after Area",
		"Area NOT IN ('a')":            "uses NOT after Area",
		"Area NOT LIKE 'a'":            "uses NOT after Area",
		"paid = TRUE":                  "compares paid with TRUE",
		"paid = true OR Area = 'n'":    "compares paid with true",
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
