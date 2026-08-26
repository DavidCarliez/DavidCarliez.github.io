---
title: "Cover: Reversible Privacy for AI Coding Agents"
description: >-
  How Cover replaces private values with deterministic fakes before an AI
  request, then restores the originals locally without breaking agent context.
coverImage:
  alt: Cover replaces private values before an LLM request and restores them in the response.
  src: ../../assets/cover-roundtrip.svg
publishDate: 2026-08-26
tags:
  - cover
  - ai-agent-security
  - privacy
  - llm-security
  - pseudonymization
  - codex
draft: false
pinned: false
---

AI coding agents often need sensitive context to do useful work. A request can contain customer names, private IP addresses, credentials, internal hosts, or ticket data. Sending those values to an external model creates a privacy risk. Removing every value can also make the agent much less useful.

[Cover](https://github.com/DavidCarliez/cover) takes a different approach. It replaces protected values locally before the request leaves your machine. When the model repeats those replacements, Cover restores the original values in the response.

The result is simple:

> Fake values go out. Real values come back.

## Redaction solves only half of the problem

Traditional redaction removes information:

```text
Connect to [REDACTED] and inspect the logs for [REDACTED].
```

This can protect the data, but it also removes relationships that the model needs. The model cannot tell whether two redacted values refer to the same host. It cannot produce a useful command that includes the protected value.

Cover can replace a private value with a realistic fake instead:

```text
Original private IP: 10.20.30.40
Value sent to the model: 10.73.184.21
```

The model can reason about the fake IP as a normal IP address. If the model returns it, Cover translates it back to `10.20.30.40` before the agent sees the response.

The same process works for hostnames, domains, email addresses, usernames, passwords, UUIDs, URLs, aliases, and other configured values.

## Deterministic fakes preserve context

Cover uses deterministic pseudonyms. The same original value produces the same fake on one Cover installation. This remains true across requests, sessions, and restarts.

That stability matters during long investigations. If a customer name appears in several files, the model sees one consistent alias. If two private IP addresses are different, the model sees two different fake addresses.

Cover derives pseudonyms with an installation key and HMAC-SHA-256. The key cannot recover the original value. Cover stores the reverse mapping in bounded process memory for response restoration.

Different Cover installations create different pseudonyms. Two teams can therefore protect the same value without sharing one stable external identifier.

## The request and response path

Cover runs as a local HTTP proxy between an AI client and its provider or router.

1. The client sends a JSON request to Cover.
2. Cover reads the complete bounded request body.
3. Cover applies configured rules to matching string values.
4. Cover sends the transformed JSON to the upstream service.
5. Cover restores known fakes in the upstream response.
6. The client receives the original local values.

Cover supports normal JSON responses and streaming responses. It works with Codex, Claude Code, Cursor, Pi, Oh My Pi, and compatible SDKs.

The selected model does not change the privacy path. Cover can sit before an OpenAI-compatible router that selects OpenAI, Anthropic, Gemini, DeepSeek, or another model.

## More than one protection policy

Not every value needs reversible protection. Cover supports six actions:

- `pseudonymize` sends a realistic fake and restores it locally.
- `placeholder` sends an opaque token and restores it locally.
- `mask` hides the middle of the value and does not restore it.
- `redact` sends `[REDACTED]` and does not restore it.
- `block` rejects the complete request before any upstream call.
- `allow` creates an explicit exception.

Rules can use regular expressions, built-in detectors, or JSON object keys. Key rules are useful for short passwords such as `admin`. A broad password expression could miss that value or match unrelated text.

```yaml
rules:
  password_fields:
    keys: [password, passwd, pwd, passphrase]
    category: password
    action: pseudonymize
    generator: password
    priority: 220

  ipv4_addresses:
    detector: builtin_ipv4
    category: ip_address
    action: pseudonymize
    generator: ipv4
    priority: 100

  customer_name:
    pattern: '(?i)\bNIKE\b'
    category: customer
    action: pseudonymize
    generator: alias
    priority: 80
```

Cover validates rules during startup. An invalid selector, expression, action, generator, or capture group prevents the proxy from starting.

Regex and key rules cannot identify every customer name, address, or internal codename. Cover therefore offers an optional local semantic detector.

The detector uses `llama.cpp` and a small local model. It runs on the loopback interface and applies fixed time and request limits. Cover accepts only spans that occur verbatim in the input.

```sh
cover models pull
cover models status
```

## Streaming exposed an important edge case

AI providers often return text through Server-Sent Events, or SSE. Each event contains a small part of the response.

A pseudonym can cross an event boundary:

```text
event 1: "north"
event 2: "star"
```

An earlier Cover version handled values split across network writes inside one SSE event. It did not reconstruct a pseudonym split across separate semantic events.

A public technical comment identified this gap. The comment did not reveal an upstream privacy leak. The provider still received only the fake value. However, Cover could return the fake instead of the original value. That failure broke transparent restoration.

The comment led directly to a change. Cover now keeps a bounded fragment across consecutive events from the same logical channel. It restores split values in these streams:

- OpenAI Responses text and tool arguments
- OpenAI Chat Completions text and tool arguments
- Anthropic text and partial tool JSON

Cover preserves event metadata and sequence numbers. It keeps opaque `encrypted_content` unchanged. It also refuses to combine fragments from different logical channels.

The test suite checks every split position and every network write boundary. It also checks EOF handling, JSON escaping, CRLF streams, channel isolation, and complete proxy round trips.

This distinction is important. A restoration failure affects local usability. An input detection failure can expose data to the provider. Those failures need different tests and different fixes.

## Test the actual privacy boundary

The useful security question is not only whether a rule matched. The useful question is whether the provider received the protected value.

Cover includes end-to-end tests with a capture upstream. The tests inspect the exact request received by that upstream. They fail if the original protected bytes reach it.

You can inspect the local transformation without sending a request:

```sh
cover inspect request.json
```

You can also watch safe request metadata:

```sh
cover monitor
```

The default monitor excludes bodies, matched values, mappings, paths, queries, and credentials. An explicit option shows the live transformation:

```sh
cover monitor --show-content
```

This view contains sensitive data. Cover keeps it local and does not add it to the audit log. You should not use it in recorded terminals or CI logs.

## Fail closed when Cover cannot inspect safely

A privacy proxy must not forward the original request after an inspection error. Cover rejects the request when it cannot apply its policy safely.

Examples include malformed JSON, compressed request bodies, detector errors, mapping exhaustion, invalid policies, and explicit `block` rules. Cover also keeps configured clients pointed at the proxy when its daemon stops. The request then fails locally instead of bypassing Cover.

`cover doctor` checks the configuration, listener, policy, daemon, routing, audit log, and local fail-closed behavior. Its live privacy probe stops locally and does not spend model tokens.

```sh
cover doctor
cover test
```

## The security boundary is specific

Cover protects matching string values inside JSON bodies that pass through the proxy. It does not claim to identify every sensitive value.

Cover does not inspect these locations by default:

- HTTP headers, URL paths, or query strings
- image pixels or binary media
- unsupported encodings
- non-string JSON values
- fields covered by an `allow` rule
- opaque protocol fields such as `encrypted_content`
- traffic from a client that bypasses the proxy

Cover also does not reassemble a secret that someone deliberately spreads across unrelated JSON fields. An encoded input can evade detection unless a rule covers that representation.

Response restoration uses exact fake-to-original mappings. If a model reformats a fake, Cover leaves the modified fake unchanged. This can break the round trip, but it does not reveal the original value to the provider.

These limits are part of the design and documentation. They also define where future work can improve detection without making broad claims.

## Install Cover

The release installer supports Linux, macOS, and Windows. It downloads the correct archive, verifies the published checksum, and installs the binary atomically.

```sh
curl -fsSL https://raw.githubusercontent.com/DavidCarliez/cover/main/scripts/install.sh | bash
```

Then initialize Cover and test the local path:

```sh
cover init
cover start --detach
cover doctor
cover test
```

Pi and Oh My Pi users can install the companion plugin:

```sh
pi install npm:cover-plugin
```

The project is open source under the Apache 2.0 license. The source, configuration examples, tests, and release archives are available on [GitHub](https://github.com/DavidCarliez/cover).

Cover does not make external models private by declaration. It creates a local boundary that you can configure, inspect, and test. The model receives coherent fake context. Your local tools continue to use the real values.
