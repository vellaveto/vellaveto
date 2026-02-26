/**
 * SDK integration code snippet generator.
 *
 * Each snippet shows VellavetoClient construction, evaluate(), and verdict
 * handling. Matches actual SDK APIs from sdk/{python,typescript,go,java}/.
 */

import type { SdkLanguage } from "../types.js";
import { DEFAULT_PORT } from "../constants.js";

export function generateSnippet(language: SdkLanguage, apiKey: string): string {
  switch (language) {
    case "python":
      return pythonSnippet(apiKey);
    case "typescript":
      return typescriptSnippet(apiKey);
    case "go":
      return goSnippet(apiKey);
    case "java":
      return javaSnippet(apiKey);
    case "skip":
      return "";
  }
}

export function installCommand(language: SdkLanguage): string {
  switch (language) {
    case "python":
      return "pip install vellaveto";
    case "typescript":
      return "npm install vellaveto";
    case "go":
      return "go get github.com/paolovella/vellaveto/sdk/go";
    case "java":
      return "<!-- Add to pom.xml -->\n<dependency>\n  <groupId>io.vellaveto</groupId>\n  <artifactId>vellaveto-sdk</artifactId>\n  <version>4.0.0</version>\n</dependency>";
    case "skip":
      return "";
  }
}

function pythonSnippet(apiKey: string): string {
  return `from vellaveto import VellavetoClient

client = VellavetoClient(
    url="http://localhost:${DEFAULT_PORT}",
    api_key="${apiKey}",
)

result = client.evaluate(
    tool="filesystem",
    function="read_file",
    parameters={"path": "/etc/passwd"},
)

if result.verdict == "Allow":
    print("Action allowed")
elif result.verdict == "Deny":
    print(f"Action denied: {result.reason}")
elif result.verdict == "RequireApproval":
    print(f"Approval required: {result.reason}")
`;
}

function typescriptSnippet(apiKey: string): string {
  return `import { VellavetoClient } from "vellaveto";

const client = new VellavetoClient({
  baseUrl: "http://localhost:${DEFAULT_PORT}",
  apiKey: "${apiKey}",
});

const result = await client.evaluate({
  tool: "filesystem",
  function: "read_file",
  parameters: { path: "/etc/passwd" },
});

if (result.verdict === "Allow") {
  console.log("Action allowed");
} else if (result.verdict === "Deny") {
  console.log(\`Action denied: \${result.reason}\`);
} else if (result.verdict === "RequireApproval") {
  console.log(\`Approval required: \${result.reason}\`);
}
`;
}

function goSnippet(apiKey: string): string {
  return `package main

import (
	"context"
	"fmt"
	"log"

	"github.com/paolovella/vellaveto/sdk/go/vellaveto"
)

func main() {
	client := vellaveto.NewClient(
		"http://localhost:${DEFAULT_PORT}",
		vellaveto.WithAPIKey("${apiKey}"),
	)

	result, err := client.Evaluate(context.Background(), &vellaveto.Action{
		Tool:     "filesystem",
		Function: "read_file",
		Parameters: map[string]any{
			"path": "/etc/passwd",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	switch result.Verdict {
	case "Allow":
		fmt.Println("Action allowed")
	case "Deny":
		fmt.Printf("Action denied: %s\\n", result.Reason)
	case "RequireApproval":
		fmt.Printf("Approval required: %s\\n", result.Reason)
	}
}
`;
}

function javaSnippet(apiKey: string): string {
  return `import io.vellaveto.VellavetoClient;
import io.vellaveto.model.Action;
import io.vellaveto.model.EvaluationResult;

import java.util.Map;

public class Example {
    public static void main(String[] args) {
        VellavetoClient client = VellavetoClient.builder("http://localhost:${DEFAULT_PORT}")
            .apiKey("${apiKey}")
            .build();

        EvaluationResult result = client.evaluate(Action.builder()
            .tool("filesystem")
            .function("read_file")
            .parameters(Map.of("path", "/etc/passwd"))
            .build());

        switch (result.getVerdict()) {
            case "Allow" -> System.out.println("Action allowed");
            case "Deny" -> System.out.println("Action denied: " + result.getReason());
            case "RequireApproval" -> System.out.println("Approval required: " + result.getReason());
        }
    }
}
`;
}
