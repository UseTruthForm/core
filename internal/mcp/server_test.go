package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// session runs the server over a script of client messages and returns
// every response, keyed by id.
func session(t *testing.T, s *Server, msgs ...string) map[string]map[string]any {
	t.Helper()
	var out strings.Builder
	if err := s.Serve(context.Background(), strings.NewReader(strings.Join(msgs, "\n")+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]any{}
	sc := bufio.NewScanner(strings.NewReader(out.String()))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("server wrote a line that is not JSON (the stream would be corrupt): %q", sc.Text())
		}
		got[string(mustJSON(m["id"]))] = m
	}
	return got
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestProtocol(t *testing.T) {
	s := &Server{Name: "truthform", Version: "test", Tools: []Tool{
		{Name: "echo", Description: "echo", Schema: map[string]any{"type": "object"}, ReadOnly: true,
			Call: func(_ context.Context, a map[string]any) (string, error) { return "said " + a["x"].(string), nil }},
		{Name: "broken", Description: "fails", Schema: map[string]any{"type": "object"}, ReadOnly: true,
			Call: func(context.Context, map[string]any) (string, error) { return "", errors.New("target unreachable") }},
	}}
	got := session(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"x":"hi"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"broken"}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope"}}`,
		`{"jsonrpc":"2.0","id":"six","method":"resources/list"}`,
		`not json`,
		`{"jsonrpc":"2.0","id":7,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`,
	)
	if len(got) != 8 {
		t.Fatalf("want 8 responses (the notification gets none), got %d: %v", len(got), got)
	}
	init := got["1"]["result"].(map[string]any)
	if init["protocolVersion"] != "2025-06-18" || init["capabilities"].(map[string]any)["tools"] == nil {
		t.Errorf("initialize: %v", init)
	}
	if v := got["7"]["result"].(map[string]any)["protocolVersion"]; v != Versions[0] {
		t.Errorf("an unknown version should get the newest, got %v", v)
	}
	tools := got["2"]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 2 || tools[0].(map[string]any)["annotations"].(map[string]any)["readOnlyHint"] != true {
		t.Errorf("tools/list: %v", tools)
	}
	if text := got["3"]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"]; text != "said hi" {
		t.Errorf("echo: %v", got["3"])
	}
	// A tool's failure is the agent's to see (isError), not a protocol error.
	if r := got["4"]["result"].(map[string]any); r["isError"] != true || !strings.Contains(string(mustJSON(r)), "target unreachable") {
		t.Errorf("broken: %v", got["4"])
	}
	for id, code := range map[string]float64{"5": -32602, `"six"`: -32601, "null": -32700} {
		if e, _ := got[id]["error"].(map[string]any); e == nil || e["code"] != code {
			t.Errorf("id %s: want error %v, got %v", id, code, got[id])
		}
	}
}
