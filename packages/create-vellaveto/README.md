# create-vellaveto

Interactive setup wizard for [Vellaveto](https://github.com/vellaveto/vellaveto) — the MCP Tool Firewall.

## Usage

```bash
npx create-vellaveto
```

Or with your preferred package manager:

```bash
npm init vellaveto
yarn create vellaveto
pnpm create vellaveto
```

## What It Does

The wizard walks you through setting up a Vellaveto configuration:

1. Choose a policy preset (deny-by-default, permissive, enterprise, etc.)
2. Configure detection settings (injection scanning, DLP)
3. Set up audit logging
4. Generate a ready-to-use `vellaveto.toml` config file

## Requirements

- Node.js 18+

## License

See [LICENSING.md](../../LICENSING.md) for repository licensing details.
