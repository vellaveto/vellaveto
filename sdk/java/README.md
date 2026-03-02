# Vellaveto Java SDK

Java client for the [Vellaveto](https://github.com/vellaveto/vellaveto) agentic security control plane API.

**Requires Java 11+.**

## Installation

### Maven

```xml
<dependency>
  <groupId>com.vellaveto</groupId>
  <artifactId>vellaveto-java-sdk</artifactId>
  <version>6.0.0</version>
</dependency>
```

### Gradle

```groovy
implementation 'com.vellaveto:vellaveto-java-sdk:6.0.0'
```

## Quick Start

```java
import com.vellaveto.VellavetoClient;
import com.vellaveto.Action;
import com.vellaveto.EvaluationResult;
import com.vellaveto.Verdict;

import java.util.Map;

public class Example {
    public static void main(String[] args) throws Exception {
        VellavetoClient client = new VellavetoClient.Builder()
            .baseUrl("http://localhost:3000")
            .apiKey("your-api-key")
            .build();

        // Check health
        var health = client.health();
        System.out.println("Status: " + health.getStatus());

        // Evaluate a tool call
        Action action = new Action.Builder()
            .tool("filesystem")
            .function("read_file")
            .parameters(Map.of("path", "/etc/passwd"))
            .build();

        EvaluationResult result = client.evaluate(action);

        switch (result.getVerdict()) {
            case ALLOW:
                System.out.println("Allowed");
                break;
            case DENY:
                System.out.println("Denied: " + result.getReason());
                break;
            case REQUIRE_APPROVAL:
                System.out.println("Needs approval: " + result.getApprovalId());
                break;
        }
    }
}
```

### Exception Handling

```java
import com.vellaveto.PolicyDeniedException;
import com.vellaveto.ApprovalRequiredException;

try {
    client.evaluateOrThrow(action);
    // Allowed — proceed
} catch (PolicyDeniedException e) {
    System.out.println("Blocked: " + e.getReason());
} catch (ApprovalRequiredException e) {
    System.out.println("Needs approval: " + e.getApprovalId());
}
```

## API Reference

| Method | Description |
|--------|-------------|
| `health()` | Check server health |
| `evaluate(action)` | Evaluate a single action |
| `evaluateOrThrow(action)` | Evaluate; throws on deny/approval |
| `listPolicies()` | List loaded policies |
| `reloadPolicies()` | Trigger policy reload |
| `getPendingApprovals()` | List pending approvals |
| `resolveApproval(id, approved)` | Approve or deny a request |
| `discover(query, maxResults)` | Search the tool discovery index |
| `discoveryStats()` | Get discovery index statistics |
| `discoveryReindex()` | Rebuild discovery IDF weights |
| `discoveryTools(serverID, sensitivity)` | List indexed tools with optional filters |
| `projectorModels()` | List supported projector model families |
| `projectSchema(schema, modelFamily)` | Project canonical schema for a model family |

## Client Options

```java
VellavetoClient client = new VellavetoClient.Builder()
    .baseUrl("http://localhost:3000")   // Vellaveto server URL
    .apiKey("your-api-key")             // API key for authentication
    .timeout(Duration.ofSeconds(5))      // Request timeout (default 5s)
    .build();
```

## Development

```bash
# Run tests (120 tests)
mvn test

# Build
mvn package
```

## License

See [LICENSE](LICENSE) and [LICENSING.md](../../LICENSING.md) for package and repository licensing details.
