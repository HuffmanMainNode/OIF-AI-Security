# Security Policy

This project is security-sensitive and intentionally limited.

- The permission gate is a reference policy check, not an OS sandbox.
- Enforce permissions in the tool host, not only in the model prompt.
- Do not expose credentials to untrusted model inputs.
- Prompt-injection scanning is heuristic and must not be used as the sole control.
- Log policy decisions without logging secrets or unnecessary personal data.
- Test model, tool, memory, and retrieval boundaries independently.

Report vulnerabilities privately with affected revision, impact, and a minimal reproduction. Do not publish working credential-exfiltration payloads or private data.
