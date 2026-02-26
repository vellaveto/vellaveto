import * as p from "@clack/prompts";
import type { PolicyPreset, WizardState } from "../types.js";

export async function policiesStep(
  state: WizardState,
): Promise<void> {
  const preset = await p.select<PolicyPreset>({
    message: "Select a policy preset",
    options: [
      {
        value: "strict",
        label: "Strict",
        hint: "Deny-by-default. Block credentials + exfiltration. Destructive ops require approval.",
      },
      {
        value: "balanced",
        label: "Balanced (recommended)",
        hint: "Deny-by-default. Block credentials. Reads allowed, writes require approval.",
      },
      {
        value: "permissive",
        label: "Permissive",
        hint: "Allow-by-default. Only block credentials and exfiltration attempts.",
      },
    ],
    initialValue: "balanced",
  });

  if (p.isCancel(preset)) {
    p.cancel("Setup cancelled.");
    process.exit(0);
  }

  state.policyPreset = preset;
}
