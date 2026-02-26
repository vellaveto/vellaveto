import * as p from "@clack/prompts";
import type { WizardState } from "../types.js";

export async function detectionStep(
  state: WizardState,
): Promise<void> {
  const injectionEnabled = await p.confirm({
    message: "Enable injection detection?",
    initialValue: true,
  });
  if (p.isCancel(injectionEnabled)) {
    p.cancel("Setup cancelled.");
    process.exit(0);
  }
  state.injectionEnabled = injectionEnabled;

  if (injectionEnabled) {
    const injectionBlocking = await p.confirm({
      message: "Block requests with detected injections? (vs. log-only)",
      initialValue: false,
    });
    if (p.isCancel(injectionBlocking)) {
      p.cancel("Setup cancelled.");
      process.exit(0);
    }
    state.injectionBlocking = injectionBlocking;
  }

  const dlpEnabled = await p.confirm({
    message: "Enable DLP (Data Loss Prevention) scanning?",
    initialValue: true,
  });
  if (p.isCancel(dlpEnabled)) {
    p.cancel("Setup cancelled.");
    process.exit(0);
  }
  state.dlpEnabled = dlpEnabled;

  if (dlpEnabled) {
    const dlpBlocking = await p.confirm({
      message: "Block requests with DLP findings? (vs. log-only)",
      initialValue: false,
    });
    if (p.isCancel(dlpBlocking)) {
      p.cancel("Setup cancelled.");
      process.exit(0);
    }
    state.dlpBlocking = dlpBlocking;
  }

  const behavioralEnabled = await p.confirm({
    message: "Enable behavioral anomaly detection?",
    initialValue: false,
  });
  if (p.isCancel(behavioralEnabled)) {
    p.cancel("Setup cancelled.");
    process.exit(0);
  }
  state.behavioralEnabled = behavioralEnabled;
}
