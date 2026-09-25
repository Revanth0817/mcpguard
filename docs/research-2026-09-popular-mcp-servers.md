# We scanned the 236 most-downloaded MCP servers on npm. Here's what we found.

*September 2026 · mcpguard research*

MCP servers are how AI agents like Claude Code, Cursor and VS Code Copilot reach your files, databases, browsers and cloud accounts. Every server's tool descriptions go straight into the model's context, and most servers are installed with a one-line `npx` command that fetches whatever version is newest.

We wanted to know what developers are actually installing. So we took the **236 most-downloaded MCP server packages on npm** (15.4 million downloads a week combined), installed each one in an isolated sandbox, started it, and read every tool it offers, the same way an AI client does. We never called a tool.

## Headline numbers

| | |
|---|---|
| MCP server packages analysed | **236** (15.4M weekly downloads) |
| Servers that started without credentials, fully inspected | **88** |
| Tools inspected | **2,313** |
| Packages that run code automatically at install time | **26 (11%)** |
| Tools with **no** safety annotations (read-only / destructive hints) | **1,165 (50%)** |
| Servers offering a tool that runs arbitrary code or commands | **11 of 88 (12%)** |
| Servers offering high-impact actions (write, delete, send, deploy, pay…) | **38 of 88 (43%)** |
| Tool names that collide across different servers | **47** (e.g. `read_file` in 4 servers) |
| Servers exposing more than 50 tools | **11** (largest: 401 tools) |
| Tool descriptions trying to secretly steer the AI | **0 malicious · 1 grey-zone** |

## 1. Good news first: no poisoned tools in the popular set

We found **no tool poisoning** in these 236 packages: no hidden `<IMPORTANT>` blocks asking the model to read `~/.ssh`, no invisible Unicode, no instructions aimed at other servers.

That matters because it is the attack everyone worries about, and it has been demonstrated many times in research. Among the most popular packages, today, it isn't happening. The risk sits in the long tail of less-reviewed servers and in **updates**: a server that's clean today can ship a poisoned description tomorrow, and `npx -y package` will run it automatically. That's why mcpguard records approved tool definitions in a lockfile and alerts when they change.

One server's description tells the model to *"Do NOT show the user"* part of an error message. It's almost certainly a UX decision for its login flow, not an attack. But it shows how thin the line is: a tool description is a prompt, and nothing today stops it from telling the model what to hide from you.

## 2. One in nine servers runs code the moment you install it

**26 of 236 packages (11%)** define `preinstall` or `postinstall` scripts. Most are mundane: fixing file permissions, rebuilding native modules, creating a data folder, downloading a browser. One runs a script whose name suggests it reports the installation.

None of these looked malicious. But install scripts run with your full user permissions *before* you've approved anything, and they are the most common way malicious npm packages do damage. If you install MCP servers with `npx -y`, you are trusting every one of these scripts, and every future version of them.

## 3. Half of all tools don't say whether they're safe

MCP lets servers mark tools with `readOnlyHint` and `destructiveHint`, so clients can auto-approve harmless reads and always ask before destructive actions. **50% of the 2,313 tools carry no annotations at all.**

When hints are missing, clients have two bad options: ask for approval on everything (users click "always allow") or on nothing.

## 4. Code execution is a feature, and it's common

**11 of 88 servers (12%)** expose a tool that runs arbitrary code or commands: shell execution, script execution in a browser or design tool, `exec` into a Kubernetes pod. That's often the whole point of the server. But combined with prompt injection (a malicious README, issue, web page or email the agent reads), it turns "the agent read something" into "the agent ran something on my machine".

**38 of 88 (43%)** expose at least one high-impact action: writing or deleting files, sending messages, merging, deploying, cancelling orders.

## 5. Tool names collide

We found **47 tool names shared by different servers**: `read_file`, `write_file`, `list_directory` and `move_file` each appear in 3–4 servers. When two such servers are installed together, the model picks by description, and a malicious server can deliberately shadow a trusted server's tool name.

## 6. Some servers are huge

**11 servers expose more than 50 tools; the largest exposes 401.** Every tool description is sent to the model, so a single server can add tens of thousands of tokens of instructions you've never read.

## What we learned about our own scanner

This research ran mcpguard against real servers for the first time, and it made the tool better:

- The first pass produced **false positives**, e.g. a Kubernetes `context` parameter flagged as "harvesting conversation context", and "use this instead of calling individual tools" flagged as tool shadowing. We fixed the rules and added **every one of those real descriptions as regression tests**.
- It found a **crash**: a server that closed its input early brought the scanner down. Fixed, with a test.

## Limitations

- **148 of 236 servers didn't start without configuration** (mostly an API key). We analysed their package metadata but couldn't read their tools. Servers that need credentials are often the most powerful ones, so the real numbers for code execution and high-impact actions are probably higher.
- npm only; PyPI (`uvx`) and Docker-based servers are next.
- We read tool definitions; we did not audit server source code or runtime behaviour.
- Heuristics can miss novel attacks. The lockfile (detecting changes) matters more than any single rule.

## What you can do today

```bash
npx github:Revanth0817/mcpguard                # audit the MCP servers on your machine and in your repo
npx github:Revanth0817/mcpguard --connect       # also read and check every tool description
npx github:Revanth0817/mcpguard lock --connect  # approve what you have; get alerted when anything changes
```

1. **Pin versions** in your MCP configs (`package@1.2.3`, not bare `npx -y package`).
2. **Keep approval on** for tools that execute code or change things.
3. **Commit a lockfile** so a silently changed tool description fails CI instead of reaching your agent.
4. **Don't install two servers that expose the same tool names.**

## Method

- Candidates: npm search for MCP keywords (≈3,900 packages), ranked by weekly downloads; kept the 236 that ship an executable and depend on an MCP SDK.
- Each package was installed with `--ignore-scripts` into a fresh directory inside an isolated cloud sandbox, started with an **empty environment** (no credentials), and queried with `initialize` and `tools/list` only.
- Findings were produced with mcpguard's rules and **every medium-or-higher result was reviewed by hand.**

mcpguard is open source (Apache-2.0): https://github.com/Revanth0817/mcpguard
