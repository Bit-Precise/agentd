package sim

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"agentd/internal/wire/pb"
)

func fc(name, args string) *pb.FunctionCall { return &pb.FunctionCall{Name: name, Arguments: args} }

func testMCP(t *testing.T, s *stack, url string) {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "sim", Version: "1"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: url}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	var names []string
	s.eventually("office tools are listed", func() bool {
		res, err := sess.ListTools(ctx, nil)
		if err != nil {
			return false
		}
		names = names[:0]
		for _, tl := range res.Tools {
			names = append(names, tl.Name)
		}
		return strings.Contains(strings.Join(names, ","), "office__exec_command")
	})
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "office__exec_command", Arguments: map[string]any{"cmd": "echo via mcp"}})
	if err != nil || res.IsError {
		t.Fatalf("call: %v %+v", err, res)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "via mcp") || !strings.Contains(text, "Process exited with code 0") {
		t.Fatalf("mcp output: %q", text)
	}
	res, err = sess.CallTool(ctx, &mcp.CallToolParams{Name: "office__exec_command", Arguments: map[string]any{"cmd": "rm -rf /tmp/x"}})
	if err != nil || !res.IsError {
		t.Fatalf("denied call should be a tool error: %v %+v", err, res)
	}
}
