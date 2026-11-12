package saas

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/usetruthform/core/internal/readonly"
	"github.com/usetruthform/core/internal/snapshot"
)

// APIVersion is the apiVersion of every SaaS object in a snapshot.
const APIVersion = "saas.truthform.org/v1"

const (
	annSecrets = "truthform.org/secrets"
	// annParent names an item's parent. A name cannot carry it: a webhook
	// is named by its URL, which is full of slashes.
	annParent = "truthform.org/parent"
	// annUnreadable names fields a write accepts that no read returns in
	// that form, so they cannot be in a snapshot. GitHub takes an
	// environment's wait_timer and reports it reshaped inside
	// protection_rules; without this the timer was dropped silently and a
	// restore read as complete.
	annUnreadable = "truthform.org/unreadable"
	// annUnchecked says the unreadable check could not look: the response
	// schema has no envelope where the provider puts the item.
	annUnchecked = "truthform.org/unreadable-unchecked"
	tokAccount   = "{{truthform|account}}"
)

// Client is one account of one provider.
type Client struct {
	P       Provider
	Spec    *Spec
	Account string
	Token   string
	// Tokens, when set, gives each request its token instead of Token: a
	// sign-in that refreshes during a long run.
	Tokens oauth2.TokenSource
	HTTP   *http.Client
	pace   *pacer // shared by copies, so one budget is kept for the account; NewClient sets it
}

// NewClient connects to an account. readOnly puts every request behind
// the read-only guard.
func NewClient(p Provider, spec *Spec, account, token string, readOnly bool) *Client {
	hc := &http.Client{}
	if readOnly {
		hc = readonly.Client()
	}
	if p.Derive != nil {
		p.Collections = append(append([]Collection(nil), p.Collections...), Derive(spec, p.Derive, p.Collections)...)
	}
	return &Client{P: p, Spec: spec, Account: account, Token: token, HTTP: hc, pace: &pacer{}}
}

// ErrNotFound means the item does not exist.
var ErrNotFound = errors.New("not found")

// do sends one request and unwraps the provider's envelope. It returns the
// payload, the whole decoded body (Cloudflare's paging sits beside the
// payload, in result_info) and the response (GitHub's paging is a header).
func (c *Client) do(ctx context.Context, method, path string, body any) (any, *http.Response, error) {
	v, _, resp, err := c.call(ctx, method, path, body)
	return v, resp, err
}

// call sends one request, waiting out the provider's rate limits as it
// documents them (ratelimit.go): a read is sent again after the wait, a
// write never is.
func (c *Client) call(ctx context.Context, method, path string, body any) (any, map[string]any, *http.Response, error) {
	for try := 1; ; try++ {
		v, whole, resp, wait, err := c.once(ctx, method, path, body)
		if wait < 0 || method != http.MethodGet || try == rateTries {
			return v, whole, resp, err
		}
		if wait == 0 {
			wait = time.Minute << (try - 1) // GitHub: at least a minute, then longer
		}
		if wait > rateWaitCap {
			return v, whole, resp, fmt.Errorf("%w (the limit resets in %s, past the %s a capture waits)", err, wait.Round(time.Second), rateWaitCap)
		}
		if serr := c.pace.sleep(ctx, wait); serr != nil {
			if ctx.Err() != nil {
				return v, whole, resp, serr // cancelled: not throttled
			}
			return v, whole, resp, fmt.Errorf("%s %s: %w", method, path, serr)
		}
	}
}

// once sends a request one time. wait is -1 unless the provider refused it
// for its rate limit, and then how long it asked to wait (0: not said).
func (c *Client) once(ctx context.Context, method, path string, body any) (v any, whole map[string]any, resp *http.Response, wait time.Duration, err error) {
	wait = -1
	if err := c.pace.wait(ctx); err != nil {
		if ctx.Err() != nil {
			return nil, nil, nil, -1, err
		}
		return nil, nil, nil, -1, fmt.Errorf("%s %s: %w", method, path, err)
	}
	v, whole, resp, b, err := c.send(ctx, method, path, body)
	if resp == nil {
		return v, whole, resp, -1, err
	}
	// The budget is spent: nothing more is sent until it refills, so
	// Cloudflare never locks the account out for 5 minutes.
	if d := untilReset(resp); d > 0 {
		c.pace.hold(clock().Add(d))
	}
	if err != nil {
		if ok, d := limited(resp, b); ok {
			wait = d
		}
	}
	return v, whole, resp, wait, err
}

// send is one request and its decoded answer; b is the raw body.
func (c *Client) send(ctx context.Context, method, path string, body any) (any, map[string]any, *http.Response, []byte, error) {
	u := path
	if !strings.HasPrefix(u, "http") {
		u = c.P.Base + path
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for k, v := range c.P.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	token := c.Token
	if c.Tokens != nil {
		t, err := c.Tokens.Token()
		if err != nil {
			return nil, nil, nil, nil, err
		}
		token = t.AccessToken
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, resp, b, fmt.Errorf("%s %s: %w", method, path, ErrNotFound)
	}
	if resp.StatusCode >= 300 {
		return nil, nil, resp, b, fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var v any
	if len(b) > 0 {
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, nil, resp, b, fmt.Errorf("%s %s: %w", method, path, err)
		}
	}
	whole, _ := v.(map[string]any)
	if c.P.Envelope != "" {
		if ok, _ := whole["success"].(bool); whole != nil && whole["success"] != nil && !ok {
			return nil, nil, resp, b, fmt.Errorf("%s %s: %v", method, path, whole["errors"])
		}
		return whole[c.P.Envelope], whole, resp, b, nil
	}
	return v, whole, resp, b, nil
}

var nextRE = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// list reads every page of a collection.
func (c *Client) list(ctx context.Context, path, array string) ([]map[string]any, error) {
	var out []map[string]any
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	size := c.P.PageSize
	if size == 0 {
		size = 100
	}
	next := path + sep + fmt.Sprintf("per_page=%d", size)
	for page := 1; next != ""; page++ {
		v, whole, resp, err := c.call(ctx, "GET", next, nil)
		if err != nil {
			return nil, err
		}
		items, _ := v.([]any)
		if m, ok := v.(map[string]any); ok && array != "" {
			items, _ = m[array].([]any)
		}
		for _, it := range items {
			if m, ok := it.(map[string]any); ok {
				out = append(out, m)
			}
		}
		next = ""
		switch c.P.Paging {
		case "link":
			if m := nextRE.FindStringSubmatch(resp.Header.Get("Link")); m != nil {
				next = m[1]
			}
		case "page":
			info, _ := whole["result_info"].(map[string]any)
			if total, _ := info["total_pages"].(float64); float64(page) < total {
				next = path + sep + fmt.Sprintf("per_page=%d&page=%d", size, page+1)
			}
		}
	}
	return out, nil
}

func (c *Client) unavailable(err error) bool {
	for _, m := range c.P.Unavailable {
		if strings.Contains(err.Error(), m) {
			return true
		}
	}
	return false
}

// item is one captured item with what is needed to name and restore it.
type item struct {
	col    *Collection
	raw    map[string]any
	parent *item
	name   string
	spec   map[string]any
	masked []string
}

// itemName is what names an item in a snapshot.
func itemName(col *Collection, raw map[string]any) string {
	if col.Singleton {
		return "settings"
	}
	var names []string
	for _, f := range col.Name {
		v := stringOf(field(raw, f))
		if secretURL(v) {
			v = urlName(v)
		}
		names = append(names, v)
	}
	return strings.Join(names, " ")
}

func (it *item) fullName() string {
	if it.parent != nil {
		return it.parent.fullName() + "/" + it.name
	}
	return it.name
}

// writes is everything a collection's writes accept.
// unreadable lists the top-level state fields a collection's read never
// returns: fields both its create and its update accept (for an item a PUT
// creates and updates, that PUT's), absent from the read's response
// schema. A field only the create takes (auto_init, license_template) is
// a one-time input, and one only the update takes (a label's new_name) is
// an action; neither is state a snapshot could hold, and naming them made
// every repository and label in the real TruthForm capture look lossy.
// With no response schema nothing is claimed: absence of evidence is not
// reported as a gap.
func (c *Client) unreadable(col *Collection) []string {
	u, _ := c.unreadableChecked(col)
	return u
}

// unreadableChecked is unreadable, and why the check could not look when
// a response schema exists but lacks the provider's envelope: that is not
// the same as nothing unreadable, and is said so.
func (c *Client) unreadableChecked(col *Collection) ([]string, string) {
	var read *Fields
	path := col.List
	if col.Get != "" {
		path = col.Get
	}
	if r := c.Spec.ResponseSchema(path, "get"); r != nil {
		f := c.Spec.fields(r, 0)
		if read = c.enveloped(f); read == nil && f != nil && !f.Any {
			return nil, fmt.Sprintf("the read's response schema (%s) has no %q envelope, so which fields it returns was not checked", path, c.P.Envelope)
		}
		if read != nil && col.Get == "" && !col.Singleton {
			if col.Array != "" && read.Children[col.Array] != nil {
				read = read.Children[col.Array]
			}
			read = read.Items
		}
	}
	w := c.Spec.RequestFields(col.Create, col.createMethod())
	var u *Fields
	if col.Update != "" {
		u = c.Spec.RequestFields(col.Update, col.updateMethod())
	}
	if read == nil || read.Any || w == nil {
		return nil, ""
	}
	var out []string
	for _, k := range sortedKeys(w.Children) {
		if u != nil && u.Children[k] == nil {
			continue
		}
		if read.Children[k] == nil && !hasString(col.Name, k) {
			out = append(out, k)
		}
	}
	return out, ""
}

// enveloped is a response's fields inside the provider's envelope
// (Cloudflare's result), where the item is; without one, the response.
func (c *Client) enveloped(f *Fields) *Fields {
	if c.P.Envelope == "" || f == nil {
		return f
	}
	return f.Children[c.P.Envelope]
}

func hasString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (c *Client) writes(col *Collection) *Fields {
	fs := []*Fields{c.Spec.RequestFields(col.Create, col.createMethod())}
	if col.Update != "" {
		fs = append(fs, c.Spec.RequestFields(col.Update, col.updateMethod()))
	}
	return union(fs...)
}

// inventory reads every collection, parents first.
func (c *Client) inventory(ctx context.Context) ([]*item, []snapshot.Coverage, error) {
	byKind := map[string][]*item{}
	var all []*item
	var cov []snapshot.Coverage
	for i := range c.P.Collections {
		col := &c.P.Collections[i]
		parents := []*item{nil}
		if col.Parent != "" {
			parents = byKind[col.Parent]
		}
		w := c.writes(col)
		cv := snapshot.Coverage{Resource: col.Kind, Kind: col.Kind}
		// One coverage line covers every parent. A failure is never
		// overwritten by a later parent's milder answer: a 502 on one
		// repository's rulesets, then "Upgrade to GitHub Pro" on the next,
		// read as "not available on this plan" and the capture as complete
		// (review, 2026-10-22).
		note := func(msg string) {
			if !strings.HasPrefix(cv.NotCaptured, "list failed") {
				cv.NotCaptured = msg
			}
		}
		for _, p := range parents {
			var praw map[string]any
			if p != nil {
				praw = p.raw
			}
			path, ok := col.listPath(c.Account, praw)
			if !ok {
				return nil, nil, fmt.Errorf("%s: cannot fill %s", col.Kind, col.List)
			}
			var items []map[string]any
			var err error
			if col.Singleton {
				var v any
				if v, _, err = c.do(ctx, "GET", path, nil); err == nil {
					m, _ := v.(map[string]any)
					items = []map[string]any{m}
				}
			} else {
				items, err = c.list(ctx, path, col.Array)
			}
			if err != nil {
				if c.unavailable(err) {
					note("not available on this account's plan: " + err.Error())
					continue
				}
				// GitHub answers 404 both for "not enabled" (Pages) and for
				// "not visible to this token", to hide what exists. Not a
				// failure, and not proof of absence: said as such.
				if errors.Is(err, ErrNotFound) {
					note("not found: not enabled here, or not visible to this token")
					continue
				}
				cv.NotCaptured = "list failed: " + err.Error()
				break
			}
			for _, raw := range items {
				// Not counted in the coverage either: the count is part of
				// the snapshot's digest, and a capture taken during a
				// renewal would no longer equal one taken after it.
				if col.Transient != nil && col.Transient(raw) != "" {
					continue
				}
				if col.Get != "" {
					gp, ok := expand(col.Get, col.Bind, c.Account, praw, raw)
					if !ok {
						return nil, nil, fmt.Errorf("%s: cannot fill %s", col.Kind, col.Get)
					}
					full, _, err := c.do(ctx, "GET", gp, nil)
					if err != nil {
						if !strings.HasPrefix(cv.NotCaptured, "list failed") {
							cv.NotCaptured = "list failed: read " + gp + ": " + err.Error()
						}
						break
					}
					raw, _ = full.(map[string]any)
				}
				it := &item{col: col, raw: raw, parent: p}
				it.name = itemName(col, raw)
				it.spec = c.specOf(col, w, raw, &it.masked)
				byKind[col.Kind] = append(byKind[col.Kind], it)
				all = append(all, it)
				cv.Captured++
			}
		}
		cov = append(cov, cv)
	}
	return all, cov, nil
}

// specOf is what a capture keeps of an item: what the writes accept, plus
// the fields that name it. Those are identity even when no write body
// carries them: GitHub creates an environment with PUT .../environments/
// {environment_name}, so its name is in the path, not the body, and a
// spec without it could not be restored.
func (c *Client) specOf(col *Collection, w *Fields, raw map[string]any, masked *[]string) map[string]any {
	kept, _ := keep(raw, w, "", masked)
	spec, _ := kept.(map[string]any)
	if spec == nil {
		spec = map[string]any{}
	}
	for _, f := range col.Name {
		if v := field(raw, f); v != nil && !strings.Contains(f, ".") {
			spec[f] = v
		}
	}
	return tokenize(spec, c.Account)
}

// tokenize replaces the account where it is structural, so a snapshot of
// one organisation or account restores into another: a value that is the
// account, or a path or URL segment (/TruthForm/). Never inside prose: the
// TruthForm organisation's repository describes itself as "TruthForm core:
// ...", and replacing that would rewrite the description in every target.
func tokenize(spec map[string]any, account string) map[string]any {
	if account == "" {
		return spec
	}
	seg := regexp.MustCompile(`(^|/)` + regexp.QuoteMeta(account) + `(/|$)`)
	return rewrite(spec, func(s string) string {
		if s == account {
			return tokAccount
		}
		return seg.ReplaceAllString(s, "${1}"+tokAccount+"${2}")
	}).(map[string]any)
}

func rewrite(v any, fn func(string) string) any {
	switch c := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(c))
		for k, x := range c {
			out[fn(k)] = rewrite(x, fn)
		}
		return out
	case []any:
		out := make([]any, len(c))
		for i, x := range c {
			out[i] = rewrite(x, fn)
		}
		return out
	case string:
		return fn(c)
	}
	return v
}

// Capture reads the account's configuration.
func (c *Client) Capture(ctx context.Context) (snapshot.Snapshot, error) {
	items, cov, err := c.inventory(ctx)
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	snap := snapshot.Snapshot{Platform: "saas/" + c.P.Name, ServerVersion: specVersion(c.Spec), Policy: "default", Coverage: cov}
	seen := map[string]bool{}
	for _, it := range items {
		meta := map[string]any{"name": it.fullName()}
		ann := map[string]any{}
		if len(it.masked) > 0 {
			sort.Strings(it.masked)
			ann[annSecrets] = strings.Join(it.masked, ",")
		}
		if it.parent != nil {
			ann[annParent] = it.parent.fullName()
		}
		if u, why := c.unreadableChecked(it.col); len(u) > 0 {
			ann[annUnreadable] = strings.Join(u, ",")
		} else if why != "" {
			ann[annUnchecked] = why
		}
		if len(ann) > 0 {
			meta["annotations"] = ann
		}
		obj := snapshot.Object{Body: map[string]any{"apiVersion": APIVersion, "kind": it.col.Kind, "metadata": meta, "spec": it.spec}}
		if seen[obj.Key()] {
			return snapshot.Snapshot{}, fmt.Errorf("%s: two items are named %q; the descriptor's name fields do not identify them", it.col.Kind, it.fullName())
		}
		seen[obj.Key()] = true
		snap.Objects = append(snap.Objects, obj)
	}
	for i := range c.P.Collections {
		col := &c.P.Collections[i]
		p := c.writes(col).Paths()
		snap.Schemas = append(snap.Schemas, snapshot.TypeSchema{APIVersion: APIVersion, Kind: col.Kind, Fields: p})
	}
	sort.Slice(snap.Objects, func(i, j int) bool { return snap.Objects[i].Key() < snap.Objects[j].Key() })
	return snap, nil
}

func specVersion(s *Spec) string {
	info, _ := s.doc["info"].(map[string]any)
	v, _ := info["version"].(string)
	return v
}

// RestoreOptions supplies values the API never returns (webhook secrets),
// keyed "kind/name".
type RestoreOptions struct {
	Values map[string]map[string]any
	// Update brings an existing item that differs in line with the
	// snapshot, through its update operation (or the PUT that creates it).
	Update bool
	// DryRun reads the target and reports each write the restore would
	// make ("would create", "would update"), and makes none.
	DryRun bool
	// Present lists kinds the restore only finds in the target (the zone a
	// subdomain restore writes records into): one there is used as it is,
	// never changed, and one missing is not made.
	Present map[string]bool
	// Allow, when set, is asked before every write, with the item the
	// write would change (nil for a create); a reason refuses the write.
	Allow func(o snapshot.Object, existing map[string]any) string
	// Existing, when set, is given the spec of an item already in the
	// target before it is compared with the snapshot's, and returns the
	// spec to compare.
	Existing func(kind string, spec map[string]any) map[string]any
}

// Restore creates what is missing, parents first. An item that exists is
// reported applied when identical; when different it is left alone unless
// Update is set. A setting (singleton) is applied without Update only when
// this restore created its parent: there the setting is part of the
// restore, while on an existing parent it would change something live.
func (c *Client) Restore(ctx context.Context, s snapshot.Snapshot, opt RestoreOptions) []snapshot.Result {
	kindIndex := map[string]int{}
	for i, col := range c.P.Collections {
		kindIndex[col.Kind] = i
	}
	objs := append([]snapshot.Object(nil), s.Objects...)
	sort.SliceStable(objs, func(i, j int) bool { return kindIndex[objs[i].Kind()] < kindIndex[objs[j].Kind()] })

	targets := map[string]map[string]any{}  // kind|fullName -> raw item in the target
	listed := map[string]map[string]*item{} // kind|parentFullName -> existing items by name
	made := map[string]bool{}               // kind|fullName created by this restore
	// What the snapshot holds of each kind that has a Slot, to tell an item
	// that changed from one that is new.
	want := wanted{names: map[string]map[string]bool{}, slots: map[string]map[string][]string{}}
	for _, o := range objs {
		i, ok := kindIndex[o.Kind()]
		if !ok || len(c.P.Collections[i].Slot) == 0 {
			continue
		}
		col := &c.P.Collections[i]
		parentName, own := place(col, o)
		lk := col.Kind + "|" + parentName
		if want.names[lk] == nil {
			want.names[lk], want.slots[lk] = map[string]bool{}, map[string][]string{}
		}
		spec, _ := o.Body["spec"].(map[string]any)
		own = nameKey(col, spec, own)
		want.names[lk][own] = true
		want.slots[lk][slotOf(col, spec)] = append(want.slots[lk][slotOf(col, spec)], own)
	}
	var results []snapshot.Result
	for _, o := range objs {
		res := snapshot.Result{Key: o.Key()}
		res.OK, res.Detail = c.restoreOne(ctx, o, targets, listed, made, want, opt)
		results = append(results, res)
	}
	return results
}

// wanted is the snapshot's items of the kinds that have a Slot, by where
// they are listed (kind|parentFullName): their names, and the names in
// each slot.
type wanted struct {
	names map[string]map[string]bool
	slots map[string]map[string][]string
}

// place is an object's parent's full name and its own name under it.
func place(col *Collection, o snapshot.Object) (parentName, own string) {
	full := o.Name()
	if col.Parent == "" {
		return "", full
	}
	ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
	parentName, _ = ann[annParent].(string)
	return parentName, strings.TrimPrefix(full, parentName+"/")
}

// nameKey is the name an item is looked up by. An address or an alias is
// the same record whatever the case of its content (a CNAME's host, an
// IPv6 address's hex digits), and a provider may store it in another case
// than it was given. Looked up exactly, the snapshot's record was then
// "missing" beside its own twin: a restore reported it as changed, and
// --update sent the same write on every run without ever matching.
func nameKey(col *Collection, spec map[string]any, name string) string {
	if col.OneAnswer != nil && col.OneAnswer(spec) {
		return strings.ToLower(name)
	}
	return name
}

// sameButCase returns the target's spec with each naming field that
// differs from the snapshot's only by case set to the snapshot's, for an
// item nameKey folds: that difference is not a difference.
func sameButCase(col *Collection, spec, exSpec map[string]any) map[string]any {
	if col.OneAnswer == nil || !col.OneAnswer(spec) {
		return exSpec
	}
	out := exSpec
	for _, f := range col.Name {
		a, b := stringOf(spec[f]), stringOf(exSpec[f])
		if a != b && strings.EqualFold(a, b) {
			if canon(out) == canon(exSpec) {
				out = deepCopy(exSpec)
			}
			out[f] = spec[f]
		}
	}
	return out
}

// slotOf is where an item is: its Slot fields. DNS compares names and
// types without regard to case.
func slotOf(col *Collection, spec map[string]any) string {
	var out []string
	for _, f := range col.Slot {
		out = append(out, strings.ToLower(stringOf(field(spec, f))))
	}
	return strings.Join(out, " ")
}

// changed handles a snapshot item that is not in the target by name, of a
// kind whose name holds its content (a DNS record). handled is false when
// the item is simply new, and the caller creates it.
//
// Without this, a record whose address changed since the capture was only
// ever "missing": the restore created the snapshot's beside the one
// there, reported success, and DNS answered with both, the stale address
// included. The same happened with --update, which had nothing to update.
//
// In the item's slot (a record's type and name) the target may hold items
// the snapshot does not have. With none, the item is new: several records
// at one name is ordinary DNS. With exactly one, and exactly one of the
// snapshot's missing there, that one is this item with other content: it
// is reported, and --update changes it where it is. With any other count
// which replaces which cannot be known, and a guess would point a name at
// the wrong server, so nothing is written there.
//
// That holds for a kind of item with one answer per slot (an address, an
// alias). For the rest (TXT, MX) another value in the slot says nothing
// about this one: the item is created, and note names what is beside it.
func (c *Client) changed(ctx context.Context, col *Collection, o snapshot.Object, lk, own string, spec, parentRaw map[string]any,
	targets map[string]map[string]any, listed map[string]map[string]*item, want wanted, opt RestoreOptions) (handled, ok bool, detail, note string) {
	slot := slotOf(col, spec)
	var others []string
	for name, it := range listed[lk] {
		if slotOf(col, it.spec) == slot && !want.names[lk][name] {
			others = append(others, name)
		}
	}
	if len(others) == 0 {
		return false, false, "", ""
	}
	sort.Strings(others)
	missing := 0
	for _, n := range want.slots[lk][slot] {
		if _, there := listed[lk][n]; !there {
			missing++
		}
	}
	// What an item holds beyond where it is: a record's content.
	holds := func(it *item) string {
		var out []string
		for _, f := range col.Name {
			if !hasString(col.Slot, f) {
				out = append(out, stringOf(field(it.spec, f)))
			}
		}
		return strings.Join(out, " ")
	}
	var there []string
	for _, n := range others {
		there = append(there, holds(listed[lk][n]))
	}
	if col.OneAnswer != nil && !col.OneAnswer(spec) {
		return false, false, "", "; the target also holds " + strings.Join(there, ", ") + " there, which the snapshot does not have"
	}
	if missing != 1 || len(others) != 1 {
		return true, false, fmt.Sprintf("not created: the target holds %s there, which the snapshot does not have, and %d of the snapshot's are missing; which replaces which is not known, so nothing is written there. Delete what should go, then run again",
			strings.Join(there, ", "), missing), ""
	}
	ex := listed[lk][others[0]]
	exSpec := ex.spec
	if opt.Existing != nil {
		exSpec = opt.Existing(col.Kind, exSpec)
	}
	exSpec = sameButCase(col, spec, exSpec)
	var keys []string
	for _, k := range sortedKeys(spec) {
		if canon(spec[k]) != canon(exSpec[k]) {
			keys = append(keys, k)
		}
	}
	differs := "already exists and differs (" + strings.Join(keys, ", ") + "; the target holds " + holds(ex) + ")"
	if !opt.Update {
		return true, false, differs + "; not modified (--update modifies it)", ""
	}
	if opt.Allow != nil {
		if why := opt.Allow(o, ex.raw); why != "" {
			return true, false, differs + "; not modified: " + why, ""
		}
	}
	if opt.DryRun {
		return true, true, "would update (" + strings.Join(keys, ", ") + ")", ""
	}
	// listed is left as it was read: an update needs exactly one of the
	// snapshot's missing in the slot, so no later item of this run looks
	// there again.
	ok, detail = c.update(ctx, col, o, ex, spec, parentRaw, keys, targets, opt)
	return true, ok, detail, ""
}

func (c *Client) restoreOne(ctx context.Context, o snapshot.Object, targets map[string]map[string]any, listed map[string]map[string]*item, made map[string]bool, want wanted, opt RestoreOptions) (bool, string) {
	idx := -1
	for i, col := range c.P.Collections {
		if col.Kind == o.Kind() {
			idx = i
		}
	}
	if idx < 0 {
		return false, "the " + c.P.Name + " descriptor has no collection " + o.Kind()
	}
	col := &c.P.Collections[idx]
	full := o.Name()
	parentName, own := "", full
	var parentRaw map[string]any
	if col.Parent != "" {
		ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
		parentName, _ = ann[annParent].(string)
		own = strings.TrimPrefix(full, parentName+"/")
		parentRaw = targets[col.Parent+"|"+parentName]
		if parentRaw == nil {
			return false, "its parent " + col.Parent + " " + parentName + " was not restored"
		}
	}
	spec, _ := o.Body["spec"].(map[string]any)
	// beside is added to what a create reports: what the target already
	// holds in the item's slot that the snapshot does not have.
	beside := ""

	// What exists under this parent in the target, read once.
	lk := col.Kind + "|" + parentName
	if listed[lk] == nil {
		path, ok := col.listPath(c.Account, parentRaw)
		if !ok {
			return false, "cannot fill " + col.List
		}
		var items []map[string]any
		var err error
		if col.Singleton {
			var v any
			if v, _, err = c.do(ctx, "GET", path, nil); err == nil {
				m, _ := v.(map[string]any)
				items = []map[string]any{m}
			}
		} else {
			items, err = c.list(ctx, path, col.Array)
		}
		if err != nil {
			return false, "cannot read the target: " + err.Error()
		}
		listed[lk] = map[string]*item{}
		w := c.writes(col)
		for _, raw := range items {
			if col.Get != "" {
				if gp, ok := expand(col.Get, col.Bind, c.Account, parentRaw, raw); ok {
					if full, _, err := c.do(ctx, "GET", gp, nil); err == nil {
						raw, _ = full.(map[string]any)
					}
				}
			}
			it := &item{col: col, raw: raw}
			it.spec = c.specOf(col, w, raw, &it.masked)
			listed[lk][nameKey(col, it.spec, itemName(col, raw))] = it
		}
	}
	own = nameKey(col, spec, own)
	if ex, ok := listed[lk][own]; ok && opt.Present[col.Kind] {
		targets[col.Kind+"|"+full] = ex.raw
		return true, "present; used as it is"
	} else if !ok && opt.Present[col.Kind] {
		return false, "not in the target, and this restore does not make one"
	}
	if ex, ok := listed[lk][own]; ok {
		targets[col.Kind+"|"+full] = ex.raw
		exSpec := ex.spec
		if opt.Existing != nil {
			exSpec = opt.Existing(col.Kind, exSpec)
		}
		exSpec = sameButCase(col, spec, exSpec)
		if canon(exSpec) == canon(spec) {
			return true, "already present and identical"
		}
		var changed []string
		for _, k := range sortedKeys(spec) {
			if canon(spec[k]) != canon(exSpec[k]) {
				changed = append(changed, k)
			}
		}
		newParent := col.Parent != "" && made[col.Parent+"|"+parentName]
		if !opt.Update && !(col.Singleton && newParent) {
			return false, "already exists and differs (" + strings.Join(changed, ", ") + "); not modified (--update modifies it)"
		}
		if opt.Allow != nil {
			if why := opt.Allow(o, ex.raw); why != "" {
				return false, "already exists and differs (" + strings.Join(changed, ", ") + "); not modified: " + why
			}
		}
		if opt.DryRun {
			return true, "would update (" + strings.Join(changed, ", ") + ")"
		}
		if !col.Singleton {
			return c.update(ctx, col, o, ex, spec, parentRaw, changed, targets, opt)
		}
	} else if len(col.Slot) > 0 {
		handled, ok, detail, note := c.changed(ctx, col, o, lk, own, spec, parentRaw, targets, listed, want, opt)
		if handled {
			return ok, detail
		}
		beside = note
	}

	desired := rewrite(deepCopy(spec), func(s string) string { return strings.ReplaceAll(s, tokAccount, c.Account) }).(map[string]any)
	vals := opt.Values[o.Kind()+"/"+full]
	merge(desired, vals)
	cf := c.Spec.RequestFields(col.Create, col.createMethod())
	body, _ := forWrite(desired, cf)
	// Required inputs no read returns (a secret's encrypted_value and
	// key_id) must be supplied; sending the request without them would
	// only be refused.
	var need []string
	bm, _ := body.(map[string]any)
	for _, r := range c.Spec.Required(col.Create, col.createMethod()) {
		if _, ok := bm[r]; !ok {
			need = append(need, r)
		}
	}
	// An item named by a secret (a webhook named by a credential-bearing
	// URL) cannot be created without it: the snapshot holds neither.
	if ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any); ann != nil {
		secrets, _ := ann[annSecrets].(string)
		for _, f := range col.Name {
			if strings.Contains(","+secrets+",", ","+f+",") && field(vals, f) == nil {
				need = append(need, f)
			}
		}
	}
	if len(need) > 0 {
		return false, "needs " + strings.Join(need, ", ") + ", which the API never returns or the snapshot does not keep; supply them with --values"
	}
	// A PUT-created item's path names it (environments/{environment_name}).
	path, ok := expand(col.Create, col.Bind, c.Account, parentRaw, desired)
	if !ok {
		return false, "cannot fill " + col.Create
	}
	if opt.Allow != nil {
		if why := opt.Allow(o, nil); why != "" {
			return false, "not created: " + why
		}
	}
	if opt.DryRun {
		targets[col.Kind+"|"+full] = desired
		made[col.Kind+"|"+full] = true
		return true, "would create" + beside
	}
	created, _, err := c.do(ctx, col.createMethod(), path, body)
	if err != nil {
		return false, err.Error()
	}
	raw, _ := created.(map[string]any)
	if col.Singleton {
		targets[col.Kind+"|"+full] = desired
		return true, "applied"
	}
	// Settings the create does not take (a repository's has_wiki) are
	// applied by the update straight after. Only then: every label and
	// hook would otherwise cost a second write.
	uf := c.Spec.RequestFields(col.Update, col.updateMethod())
	upd, _ := forWrite(desired, uf)
	extra := false
	if um, ok := upd.(map[string]any); ok {
		for k := range um {
			if _, sent := bm[k]; !sent {
				extra = true
			}
		}
	}
	if col.Update != "" && extra {
		// GitHub answers a variable's create with an empty object: the item
		// is named by what was sent.
		up, ok := expand(col.Update, col.Bind, c.Account, parentRaw, raw)
		if !ok {
			up, ok = expand(col.Update, col.Bind, c.Account, parentRaw, desired)
		}
		if !ok {
			return false, "created, but cannot fill " + col.Update
		}
		if updated, _, err := c.do(ctx, col.updateMethod(), up, upd); err != nil {
			return false, "created, but its settings were not applied: " + err.Error()
		} else if m, ok := updated.(map[string]any); ok {
			raw = m
		}
	}
	if len(raw) == 0 {
		raw = desired // the create answered with nothing (a variable)
	}
	targets[col.Kind+"|"+full] = raw
	made[col.Kind+"|"+full] = true
	detail := "created" + beside
	ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
	if u, _ := ann[annUnreadable].(string); u != "" {
		var unset []string
		for _, f := range strings.Split(u, ",") {
			if _, ok := vals[f]; !ok {
				unset = append(unset, f)
			}
		}
		if len(unset) > 0 {
			detail += "; never read back, so not restored: " + strings.Join(unset, ", ")
		}
	}
	if s, _ := ann[annSecrets].(string); s != "" {
		var missing []string
		for _, p := range strings.Split(s, ",") {
			if field(vals, p) == nil {
				missing = append(missing, p)
			}
		}
		if len(missing) > 0 {
			detail += "; secret, not supplied: " + strings.Join(missing, ", ")
		}
	}
	return true, detail
}

// update brings an existing item in line: through its update operation
// when the API has one, else by the PUT that creates it (an environment, a
// variable), which sets the item whole. A masked secret is never in the
// snapshot, so an update that would send the item without it is refused
// unless the value is supplied.
func (c *Client) update(ctx context.Context, col *Collection, o snapshot.Object, ex *item, spec, parentRaw map[string]any,
	changed []string, targets map[string]map[string]any, opt RestoreOptions) (bool, string) {
	full := o.Name()
	desired := rewrite(deepCopy(spec), func(s string) string { return strings.ReplaceAll(s, tokAccount, c.Account) }).(map[string]any)
	vals := opt.Values[o.Kind()+"/"+full]
	merge(desired, vals)
	differs := "already exists and differs (" + strings.Join(changed, ", ") + ")"
	ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
	if s, _ := ann[annSecrets].(string); s != "" {
		var missing []string
		for _, p := range strings.Split(s, ",") {
			if field(vals, p) == nil {
				missing = append(missing, p)
			}
		}
		if len(missing) > 0 {
			return false, differs + "; not updated: its secret fields (" + strings.Join(missing, ", ") + ") are never returned, so the update would send it without them; supply them with --values"
		}
	}
	var tmpl, method string
	item := ex.raw
	switch {
	case col.Update != "":
		tmpl, method = col.Update, col.updateMethod()
	case col.createMethod() == "PUT":
		tmpl, method, item = col.Create, "PUT", desired
	default:
		return false, differs + "; the API offers no way to update a " + col.Kind
	}
	path, ok := expand(tmpl, col.Bind, c.Account, parentRaw, item)
	if !ok {
		return false, differs + "; cannot fill " + tmpl
	}
	body, _ := forWrite(desired, c.Spec.RequestFields(tmpl, method))
	bm, _ := body.(map[string]any)
	var need []string
	for _, r := range c.Spec.Required(tmpl, method) {
		if _, ok := bm[r]; !ok {
			need = append(need, r)
		}
	}
	if len(need) > 0 {
		return false, differs + "; the update needs " + strings.Join(need, ", ") + ", which the API never returns; supply them with --values"
	}
	got, _, err := c.do(ctx, method, path, body)
	if err != nil {
		return false, err.Error()
	}
	if m, ok := got.(map[string]any); ok {
		targets[col.Kind+"|"+full] = m
	}
	return true, "updated (" + strings.Join(changed, ", ") + ")"
}

func merge(dst, src map[string]any) {
	for k, v := range src {
		dm, dok := dst[k].(map[string]any)
		sm, sok := v.(map[string]any)
		if dok && sok {
			merge(dm, sm)
			continue
		}
		dst[k] = v
	}
}

func deepCopy(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func canon(v any) string { b, _ := json.Marshal(v); return string(b) }

// Adapter is a SaaS account as a platform.Platform.
type Adapter struct {
	Client  *Client
	Options RestoreOptions
}

func (a *Adapter) Name() string { return "saas/" + a.Client.P.Name }

func (a *Adapter) Capture(ctx context.Context) (snapshot.Snapshot, error) {
	return a.Client.Capture(ctx)
}

func (a *Adapter) Restore(ctx context.Context, s snapshot.Snapshot) []snapshot.Result {
	return a.Client.Restore(ctx, s, a.Options)
}
