import * as p from "@clack/prompts";
import pc from "picocolors";
import type { WizardState } from "../types.js";
import { generateApiKey, isValidOrigin } from "../utils.js";

export async function securityStep(
  state: WizardState,
): Promise<void> {
  const generatedKey = generateApiKey();

  p.log.info(`Generated API key: ${pc.cyan(generatedKey)}`);

  const useGenerated = await p.confirm({
    message: "Use this API key?",
    initialValue: true,
  });

  if (p.isCancel(useGenerated)) {
    p.cancel("Setup cancelled.");
    process.exit(0);
  }

  if (useGenerated) {
    state.apiKey = generatedKey;
  } else {
    const customKey = await p.text({
      message: "Enter your API key",
      validate(value) {
        if (value.length < 8) return "API key must be at least 8 characters";
      },
    });

    if (p.isCancel(customKey)) {
      p.cancel("Setup cancelled.");
      process.exit(0);
    }

    state.apiKey = customKey;
  }

  const corsInput = await p.text({
    message: "Allowed CORS origins (comma-separated, or * for all)",
    placeholder: "http://localhost:3000",
    defaultValue: "",
  });

  if (p.isCancel(corsInput)) {
    p.cancel("Setup cancelled.");
    process.exit(0);
  }

  if (corsInput.trim()) {
    const origins = corsInput
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    const invalid = origins.filter((o) => !isValidOrigin(o));
    if (invalid.length > 0) {
      p.log.warn(
        `Skipping invalid origins: ${invalid.join(", ")}`,
      );
    }
    state.corsOrigins = origins.filter((o) => isValidOrigin(o));
  }

  const anonymous = await p.confirm({
    message: "Allow anonymous (unauthenticated) evaluate requests?",
    initialValue: false,
  });

  if (p.isCancel(anonymous)) {
    p.cancel("Setup cancelled.");
    process.exit(0);
  }

  state.anonymousMode = anonymous;
}
