# Changelog

## v0.1.0 — 2026-09-25

First public release.

- Discovers MCP configs for Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Gemini CLI and Roo (JSONC supported).
- Static config checks: hardcoded secrets, unpinned packages, `curl | sh` launchers, plain-HTTP remotes, root/home filesystem access, privileged containers, git-sourced servers, unpublished package names, known CVEs (plus OSV.dev with `--online`).
- `--connect`: reads live tool definitions over stdio and streamable HTTP (never calls a tool) and detects hidden instructions, invisible Unicode, secret-file references, exfiltration, tool shadowing, context-harvesting parameters, code-execution tools and tool-name collisions.
- `mcpguard lock`: lockfile of approved servers and tool fingerprints; alerts on rug pulls, new servers, config changes.
- Text, JSON, SARIF and Markdown output; GitHub Action.
- Rules tuned against the 236 most-downloaded MCP servers on npm (see `docs/research-2026-09-popular-mcp-servers.md`).
