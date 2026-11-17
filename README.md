# OIF AI Security

**Defensive security controls and evaluation primitives for AI models, agents, tools, and their supply chains.**

This repository implements two small, auditable safeguards: a permission gate for tool invocation requests and a heuristic scanner that flags common instruction-injection patterns in untrusted text. These are defense-in-depth examples, not a complete agent security system.

## Implemented

- Explicit tool allowlist and per-tool permission requirements.
- Deny-by-default decision when a tool is unknown or required permission is absent.
- Heuristic prompt-injection signal detection with explainable rule IDs.
- Input fixtures and unit tests.
- No network access, model calls, or third-party runtime dependency.

## Quick start

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
oif-ai-guard examples/policy.json
```

## Security model

Untrusted content can contain instructions that attempt to override system policy, reveal secrets, or trigger tool use. Treat retrieved text, files, web pages, emails, and tool outputs as data. The scanner only flags patterns; it cannot reliably determine intent and can produce false positives and false negatives.

Tool authorization must be enforced at the execution boundary. A model-generated request is never sufficient authorization. Keep secrets out of model context where possible, scope credentials narrowly, log decisions, and require human approval for consequential actions.

## Scope

This repository owns AI-specific defensive controls and test fixtures. General defensive IOC processing belongs in [OIF-Cyber-Intelligence](https://github.com/HuffmanMainNode/OIF-Cyber-Intelligence); protocol-wide compatibility tests belong in [OIF-Conformance-Lab](https://github.com/HuffmanMainNode/OIF-Conformance-Lab).
