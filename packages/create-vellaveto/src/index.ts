#!/usr/bin/env node

/**
 * create-vellaveto — CLI setup wizard for the Vellaveto MCP policy gateway
 *
 * Usage:
 *   npx create-vellaveto                  Interactive wizard (creates ./vellaveto/)
 *   npx create-vellaveto my-project       Write files to ./my-project/
 *   npx create-vellaveto --help           Show help
 *   npx create-vellaveto --version        Show version
 */

import { VERSION } from "./constants.js";
import { runWizard } from "./wizard.js";

function printHelp(): void {
  console.log(`
create-vellaveto v${VERSION}

Setup wizard for Vellaveto — MCP policy gateway

Usage:
  npx create-vellaveto [project-directory]

Arguments:
  project-directory   Directory to create (default: vellaveto)

Options:
  --help, -h          Show this help message
  --version, -v       Show version number

Examples:
  npx create-vellaveto                # Creates ./vellaveto/ with all files
  npx create-vellaveto my-project     # Creates ./my-project/ with all files
`);
}

function main(): void {
  const args = process.argv.slice(2);

  let projectDir: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    switch (arg) {
      case "--help":
      case "-h":
        printHelp();
        process.exit(0);
        break;
      case "--version":
      case "-v":
        console.log(VERSION);
        process.exit(0);
        break;
      // Keep --output as hidden alias for backwards compat
      case "--output":
      case "-o":
        i++;
        if (i >= args.length) {
          console.error("Error: --output requires a directory path");
          process.exit(1);
        }
        projectDir = args[i];
        break;
      default:
        if (arg.startsWith("-")) {
          console.error(`Unknown option: ${arg}`);
          console.error("Run with --help for usage information.");
          process.exit(1);
        }
        projectDir = arg;
    }
  }

  runWizard(projectDir).catch((err: unknown) => {
    console.error("Fatal error:", err);
    process.exit(1);
  });
}

main();
