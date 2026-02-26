import { randomBytes } from "node:crypto";

/**
 * Generate a Vellaveto API key in the format `vk_<32 hex chars>`.
 */
export function generateApiKey(): string {
  const bytes = randomBytes(16);
  return `vk_${bytes.toString("hex")}`;
}

/**
 * Escape a string for use in a TOML quoted string value.
 * Handles backslashes, double quotes, and control characters.
 */
export function escapeTomlString(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t");
}

/**
 * Validate that a string looks like a valid origin URL.
 */
export function isValidOrigin(origin: string): boolean {
  if (origin === "*") return true;
  try {
    const url = new URL(origin);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Format a list of strings as a TOML inline array.
 */
export function toTomlArray(items: string[]): string {
  const escaped = items.map((s) => `"${escapeTomlString(s)}"`);
  return `[${escaped.join(", ")}]`;
}
