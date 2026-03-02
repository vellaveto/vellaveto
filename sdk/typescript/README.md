# Vellaveto TypeScript SDK

TypeScript/JavaScript client for the [Vellaveto](https://github.com/vellaveto/vellaveto) agentic security control plane API.

## Installation

```bash
npm install @vellaveto-sdk/typescript
```

## Quick Start

```typescript
import { VellavetoClient, Verdict } from '@vellaveto-sdk/typescript';

const client = new VellavetoClient({
  baseUrl: 'http://localhost:3000',
  apiKey: 'your-api-key',
});

// Evaluate a tool call
const result = await client.evaluate({
  tool: 'filesystem',
  function: 'read_file',
  parameters: { path: '/etc/passwd' },
});

if (result.verdict === Verdict.Allow) {
  // Proceed with tool call
} else if (result.verdict === Verdict.Deny) {
  console.log(`Blocked: ${result.reason}`);
} else if (result.verdict === Verdict.RequireApproval) {
  console.log(`Needs approval: ${result.approvalId}`);
}
```

### With Exception Handling

```typescript
import { VellavetoClient, PolicyDenied, ApprovalRequired } from '@vellaveto-sdk/typescript';

const client = new VellavetoClient({ baseUrl: 'http://localhost:3000' });

try {
  await client.evaluateOrRaise({
    tool: 'http',
    function: 'fetch',
    parameters: { url: 'https://evil.com/exfil' },
  });
} catch (e) {
  if (e instanceof PolicyDenied) {
    console.log(`Denied: ${e.reason}`);
  } else if (e instanceof ApprovalRequired) {
    console.log(`Needs approval: ${e.approvalId}`);
  }
}
```

### With Evaluation Context

```typescript
const result = await client.evaluate(
  {
    tool: 'filesystem',
    function: 'write_file',
    parameters: { path: '/tmp/out.txt', content: 'data' },
  },
  {
    sessionId: 'user-session-123',
    agentId: 'my-agent',
    tenantId: 'tenant-abc',
    callChain: ['tool1', 'tool2'],
  },
);
```

## API Reference

| Method | Description |
|--------|-------------|
| `evaluate()` | Evaluate a tool call against policies |
| `evaluateOrRaise()` | Evaluate and throw on denial |
| `health()` | Check server health |
| `listPolicies()` | List configured policies |
| `reloadPolicies()` | Reload policies from config |
| `listPendingApprovals()` | Get pending approval requests |
| `approveApproval()` | Approve a pending request |
| `denyApproval()` | Deny a pending request |
| `discover()` | Search the tool discovery index |
| `discoveryStats()` | Get discovery index statistics |
| `discoveryReindex()` | Rebuild discovery IDF weights |
| `discoveryTools()` | List indexed tools with optional filters |
| `projectorModels()` | List supported projector model families |
| `projectSchema()` | Project canonical schema for a model family |

## Client Options

```typescript
const client = new VellavetoClient({
  baseUrl: 'http://localhost:3000', // Vellaveto server URL
  apiKey: 'your-api-key',           // API key for authentication
  timeout: 5000,                     // Request timeout in ms (default 5000)
  headers: {                         // Extra headers
    'X-Tenant-ID': 'acme',
  },
});
```

## Development

```bash
npm install
npm test
npm run build
```

## License

See [LICENSE](LICENSE) and [LICENSING.md](../../LICENSING.md) for package and repository licensing details.
