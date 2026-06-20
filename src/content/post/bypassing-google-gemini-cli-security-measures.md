---
title: Finding Gaps in Gemini CLI Security Boundaries
description: >-
  Two rejected Google VRP reports and one design concern from my Gemini CLI testing: a blocked-command
  bypass, an MCP startup policy bypass, and an MCP permission-scope issue.
publishDate: 2026-06-13
updatedDate: 2026-06-20
tags:
  - gemini-cli
  - ai-agent-security
  - cli-security
  - mcp
  - sandboxing
  - rejected-finding
draft: false
pinned: false
---

## Summary

I've been using Gemini CLI for a while, and I wanted to see how solid its security measures were around blocked commands and MCP/tool execution. So naturally I dug into it and it did not take long to find places where the boundary was weaker than it looked.

I ended up finding three related issues:

1. A blocked-command bypass where shell composition could let a denied command run anyway.
2. An MCP startup policy bypass where denied MCP servers could still start their local commands.
3. An MCP permission-scope issue where an approval decision could carry further than the user-visible prompt suggested.

I reported the first two to Google's VRP. Both were closed as not meeting their threshold for security tracking. I will not argue that decision here, but the behavior is still worth documenting because these security measures could be bypassed in practical, reproducible ways. The third issue is a design concern I observed during testing -- I did not report it because without a concrete sandbox-reuse demonstration the report would be too speculative for a VRP submission.

## The first issue: blocked commands and shell composition

The first report was about Gemini CLI's blocked-command behavior.

The expectation is simple. If a CLI says a command is blocked, I expect that command not to run through the agent. That expectation matters more for an agent than for a normal shell, because the model is generating commands and the user is relying on the tool to keep certain operations off limits.

A blocked-command list is weak if it catches this shape:

```sh
blocked-command arg1 arg2
```

but misses this shape:

```sh
allowed-command; blocked-command arg1 arg2
```

or the same idea through `&&`, `||`, pipelines, command substitution, subshells, or other shell features.

The bypass class was command chaining. Conceptually:

```sh
safe-looking-command && blocked-command
```

or:

```sh
safe-looking-command; blocked-command
```

If the policy engine only checks the first command, or only checks the top-level command string in a shallow way, the first command can pass policy while the shell still executes the later denied command.

That changes the guarantee from:

> blocked commands cannot run

into:

> blocked commands cannot be the first obvious token in the command string

Those are very different guarantees.

## Why shell parsing matters

This is not a Gemini-specific lesson. It is the same bug class as URL parser confusion, path normalization bugs, or checking a filesystem path before resolving symlinks.

The checker and the executor disagree about structure. The checker sees a safe-looking representation. The executor sees what will actually happen.

And when the checker and executor disagree, the executor wins.

For agent CLIs, that gap matters because the execution path usually looks like this:

1. The model proposes a command.
2. The CLI checks whether it is allowed.
3. The user assumes the check applies to the full command.
4. The shell executes every command in the chain.

If step 2 does not model step 4, the policy is not a real execution boundary.

The clean fix is to avoid shell execution for policy-controlled commands. Use an explicit argv array and execute one program. If a shell is required, the policy engine needs to parse like the shell and check every command the shell can reach. That is hard, but pretending the command string is simple does not make it safe.

## The second issue: MCP startup policy mismatch

This one took longer to find because the policy looked right on paper. Gemini CLI has a settings system where users can configure `mcp.allowed` and `mcp.excluded` to control which MCP servers can start. There is a helper function that correctly handles edge cases: treating an empty allowlist as deny-all, normalizing server name comparisons so `BlockedServer` and `blockedserver` match the same policy entry.

The startup path does not use that helper.

The startup gate in `McpClientManager.isBlockedBySettings()` has its own simpler check:

```
if the allowlist exists and has entries and the name is not in it, block
if the excludelist exists and has entries and the name is in it, block
otherwise allow
```

Two gaps follow from that:

1. **Empty allowlist treated as unrestricted.** If a user configures `mcp.allowed` with a filter that produces no intersection, the consolidated list is empty. The helper correctly treats this as deny-all. The startup gate skips the allowlist check entirely because the list has zero entries, so every server starts. The user's intent was "no MCP servers should be allowed," but the startup path says "the list is empty, so nothing is blocked."

2. **Case-sensitive comparisons.** If the policy excludes `BlockedServer`, a configured startup server named `blockedserver` passes the check because `BlockedServer !== blockedserver` in a JavaScript `includes()` call. The case mismatch seems small, but MCP server names come from configuration files, environment variables, or workspace setup. An attacker with influence over the server name can trivially differ by case.

I confirmed both with a focused audit test. The test proved that `isBlockedBySettings()` returns `false` for both an empty allowlist and a case-differing excludelist entry, while the same inputs to the normalized helper return `true`.

The surprising part is that this bypass is not about running a blocked shell command. It is about running a blocked MCP server binary. For stdio MCP servers, the configured local command starts as a child process before MCP protocol negotiation. That means `chmod`, `curl`, or any binary referenced in the MCP server config can run before Gemini has a chance to reject the connection. The negotiation fails, but the process already started.

## The third issue: MCP approvals and sandbox permission reuse

This is the most interesting design question I found -- and the one I chose not to report.

The confusing part of this issue is that it is **not** "MCP gives an attacker RCE by itself." That would be an overstatement. The issue is narrower: Gemini's permission prompt could describe one operation while the runtime effectively gave permission to a larger execution context.

Gemini CLI has safety prompts around tool execution. When a command or MCP-backed tool wants access to something sensitive, such as the filesystem or the network, Gemini asks for approval.

A simple version looks like this:

```text
Allow this command to access file A?
```

The security expectation is:

```text
I approved this exact operation, with this exact scope.
```

The design gap is that the approval could behave more like:

```text
This shell/tool execution context now has permission.
```

That distinction matters when the operation is a shell chain. Imagine Gemini runs something shaped like this:

```sh
cat ./allowed-file && cat ./other-sensitive-file
```

If Gemini prompts for the first part:

```text
Allow access to ./allowed-file?
```

and I approve it, the second command may run in the same approved context:

```sh
cat ./other-sensitive-file
```

without a second prompt.

That is the design concern. The prompt made it look like I approved one access, but the runtime could allow more than that.

## Why MCP makes this matter

MCP tools can expose sensitive capabilities. The issue is that MCP/tool execution can create long-lived or reused execution contexts, and Gemini's approval needs to bind to the exact final operation.

If approval is attached too broadly, a malicious prompt, repo, MCP server, or tool workflow can do this:

```text
1. Trigger a harmless-looking approval.
2. Get the user to approve it.
3. Run a second, more sensitive action in the same chain/context.
4. Avoid a fresh prompt.
```

## The common pattern

All three issues look different on the surface. One is about shells. Another is about MCP server configuration. The third is about tool permissions. Underneath, they are the same kind of gap.

In every case, the user-facing control describes a smaller operation than the one the system may actually execute.

For the blocked-command case:

```text
policy checks: the first visible command
executor runs: the full shell command graph
```

For the MCP startup policy case:

```text
policy checks: with the normalized helper
startup gate checks: with a different, weaker implementation
```

For the MCP approval case:

```text
prompt approves: first sensitive shell/tool segment
runtime allows: later shell/tool segments through reused sandbox permission
```

That is the agent-security version of a classic validation mistake. You do not validate one object and then execute a different object. You do not approve one scope and then let the runtime act with a larger implicit scope. And you do not implement the same security check in two places and then update only one.

## Takeaway

The useful lesson from all three findings is simple:

> Agent security controls have to bind to the real execution graph, not the first friendly-looking representation of it.

For shell commands, that means modeling what the shell will execute.

For MCP server policy, that means using one implementation for every enforcement point, not duplicating the logic in a second path with different semantics.

For MCP tools, that means scoping approval to the actual operation and any sensitive follow-on behavior.

The more autonomy these CLIs get, the less acceptable fuzzy boundaries become. If the model can plan across tools and the runtime can carry state across calls, then "the user approved something earlier" is not enough. The approval has to describe the real capability being granted.
