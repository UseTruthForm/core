// Package mcp serves tools over the Model Context Protocol: JSON-RPC 2.0,
// one message per line on stdin and stdout. It implements what a tool
// server needs (initialize, ping, tools/list, tools/call) and nothing
// else, so StackDNA carries no MCP dependency.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// Versions are the protocol revisions this server speaks, newest first. A
// client asking for one of them gets it; any other gets the newest.
var Versions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

// Tool is one tool. Call returns text for the agent; an error is a tool
// failure the agent sees and can act on (isError), not a protocol error.
type Tool struct {
	Name        string
	Description string
	Schema      map[string]any // JSON Schema of the arguments
	// ReadOnly tools change nothing at all; the hint lets a client run them
	// without asking. Destructive tools may delete or overwrite something.
	ReadOnly, Destructive bool
	Call                  func(ctx context.Context, args map[string]any) (string, error)
}

// Server is a named set of tools.
type Server struct {
	Name, Version, Instructions string
	Tools                       []Tool
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Serve answers requests from r on w until r ends. Each line is one
// message; stdout carries nothing else, since anything else written there
// would corrupt the stream (tools must not print).
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	var mu sync.Mutex
	enc := json.NewEncoder(w)
	send := func(v response) {
		mu.Lock()
		defer mu.Unlock()
		_ = enc.Encode(v)
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			send(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error: " + err.Error()}})
			continue
		}
		if len(req.ID) == 0 {
			continue // a notification (notifications/initialized): no answer
		}
		res, rerr := s.handle(ctx, req)
		out := response{JSONRPC: "2.0", ID: req.ID}
		if rerr != nil {
			out.Error = rerr
		} else {
			out.Result = res
		}
		send(out)
	}
	return sc.Err()
}

func (s *Server) handle(ctx context.Context, req request) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		v := Versions[0]
		for _, x := range Versions {
			if x == p.ProtocolVersion {
				v = x
			}
		}
		return map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": s.Name, "version": s.Version},
			"instructions":    s.Instructions,
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		tools := make([]map[string]any, 0, len(s.Tools))
		for _, t := range s.Tools {
			tools = append(tools, map[string]any{
				"name": t.Name, "description": t.Description, "inputSchema": t.Schema,
				"annotations": map[string]any{"readOnlyHint": t.ReadOnly, "destructiveHint": t.Destructive, "openWorldHint": true},
			})
		}
		return map[string]any{"tools": tools}, nil
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &rpcError{-32602, "invalid params: " + err.Error()}
		}
		for _, t := range s.Tools {
			if t.Name != p.Name {
				continue
			}
			if p.Arguments == nil {
				p.Arguments = map[string]any{}
			}
			text, err := t.Call(ctx, p.Arguments)
			if err != nil {
				return map[string]any{"content": []any{map[string]any{"type": "text", "text": err.Error()}}, "isError": true}, nil
			}
			return map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}, "isError": false}, nil
		}
		return nil, &rpcError{-32602, fmt.Sprintf("unknown tool %q", p.Name)}
	}
	return nil, &rpcError{-32601, "method not found: " + req.Method}
}
