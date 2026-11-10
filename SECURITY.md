# Security policy

This is a personal open-source project (not an official product of any employer). It contains
deliberately adversarial test content, but all of it is synthetic and runs only against simulated
tools.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting:
**Security tab -> "Report a vulnerability"** on this repository.

In scope: code execution or file/network access outside the simulated world, API-key handling
(the harness must never log, store or accept a key as an argument), unsafe deserialisation, and
dependency issues. Reports on scenario *design* (a missed attack class, a scorer blind spot) are
welcome as normal issues.

Responses are best-effort; reports will be taken seriously and credited if you like.

## Handling secrets

- `ANTHROPIC_API_KEY` is read from the environment only. Do not paste it into commands or commit it.
- Run traces (`results/`) are gitignored. They contain only synthetic canary strings, but review
  them before sharing.
