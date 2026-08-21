# Security Policy

Acta records raw coding-agent output, prompts when explicitly requested, and
workspace diffs. Treat every run bundle as sensitive even though Acta stores
new bundles with owner-only filesystem permissions.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use GitHub's private **Report a vulnerability** flow when it is available for
this repository. If it is unavailable, contact the repository owner through
their GitHub profile to establish a private channel before sharing details.

Include the affected version or commit, impact, reproduction steps, and any
suggested mitigation. Please avoid including real credentials, private source,
or captured agent sessions in the report.

Security fixes are supported on the latest release and the current `main`
branch until a formal long-term-support policy is published.
