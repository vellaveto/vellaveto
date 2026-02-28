# Vellaveto Go SDK

Go client for the [Vellaveto](https://github.com/paolovella/vellaveto) agentic security control plane API.

**Zero dependencies** — uses only the Go standard library.

## Installation

```bash
go get github.com/paolovella/vellaveto/sdk/go
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    vellaveto "github.com/paolovella/vellaveto/sdk/go"
)

func main() {
    client := vellaveto.NewClient("http://localhost:3000",
        vellaveto.WithAPIKey("your-api-key"),
    )

    // Check health
    health, err := client.Health(context.Background())
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Server status: %s\n", health.Status)

    // Evaluate an action
    result, err := client.Evaluate(context.Background(), vellaveto.Action{
        Tool:          "read_file",
        TargetPaths:   []string{"/data/report.csv"},
    }, nil, false)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Verdict: %s\n", result.Verdict)

    // Or use EvaluateOrError for typed errors
    err = client.EvaluateOrError(context.Background(), vellaveto.Action{
        Tool:          "exec_command",
        Function:      "shell",
        Parameters:    map[string]interface{}{"cmd": "ls"},
    }, nil)
    if err != nil {
        switch e := err.(type) {
        case *vellaveto.PolicyDeniedError:
            fmt.Printf("Denied: %s (policy: %s)\n", e.Reason, e.PolicyID)
        case *vellaveto.ApprovalRequiredError:
            fmt.Printf("Needs approval: %s (id: %s)\n", e.Reason, e.ApprovalID)
        default:
            log.Fatal(err)
        }
    }
}
```

## API Reference

| Method | Description |
|--------|-------------|
| `Health(ctx)` | Check server health |
| `Evaluate(ctx, action, context, trace)` | Evaluate a single action |
| `EvaluateOrError(ctx, action, context)` | Evaluate; returns typed error on deny/approval |
| `ListPolicies(ctx)` | List loaded policies |
| `ReloadPolicies(ctx)` | Trigger policy reload |
| `Simulate(ctx, action, context)` | Simulate with full trace |
| `BatchEvaluate(ctx, actions, policyConfig)` | Batch evaluate up to 100 actions |
| `ValidateConfig(ctx, config, strict)` | Validate policy configuration |
| `DiffConfigs(ctx, before, after)` | Diff two policy configs |
| `ListPendingApprovals(ctx)` | List pending approvals |
| `ApproveApproval(ctx, id)` | Approve by ID |
| `DenyApproval(ctx, id)` | Deny by ID |
| `Discover(ctx, query, maxResults, tokenBudget)` | Search the tool discovery index |
| `DiscoveryStats(ctx)` | Get discovery index statistics |
| `DiscoveryReindex(ctx)` | Rebuild discovery IDF weights |
| `DiscoveryTools(ctx, serverID, sensitivity)` | List indexed tools with optional filters |
| `ProjectorModels(ctx)` | List supported projector model families |
| `ProjectSchema(ctx, schema, modelFamily)` | Project canonical schema for a model family |

## Client Options

```go
client := vellaveto.NewClient("http://localhost:3000",
    vellaveto.WithAPIKey("key"),              // Bearer token auth
    vellaveto.WithTimeout(10 * time.Second),  // Request timeout (default 5s)
    vellaveto.WithHTTPClient(customClient),   // Custom http.Client
    vellaveto.WithHeaders(map[string]string{  // Extra headers
        "X-Tenant-ID": "acme",
    }),
)
```

## License

See [LICENSE](LICENSE) and [LICENSING.md](../../LICENSING.md)
