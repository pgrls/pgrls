# Security policy

## Reporting a vulnerability

If you believe you've found a vulnerability in pgrls itself — the linter,
the testing toolkit, the diff command, or the JSON / SARIF / GitHub
output that downstream CI parses — **please do not open a public
issue.** Email the
maintainer at **dmitrymaranik@gmail.com** with the details:

- The pgrls version (`pgrls --version`) where you observed the issue.
- A minimal reproduction: the SQL fixture or `pgrls.toml` that triggers
  the unexpected behaviour, plus the exact CLI invocation.
- The impact you believe it has — false-negative on a real bug, crash,
  arbitrary-SQL emission from `pgrls fix`, etc.

You can expect an acknowledgement within **5 business days**. Once the
issue is understood, the maintainer will work with you on a coordinated
disclosure: a fix lands first, then a release with a CVE-style note in
the CHANGELOG, then the public disclosure.

## What's in scope

- The lint rules (any false-negative on a CVE-class shape, any
  false-positive that would force a wholesale rule disable).
- The fixer output (any emitted SQL that's not idempotent, that
  overwrites intended state, or that opens a new vulnerability).
- The `pgrls diff` classification (any change incorrectly classified
  SAFE or downgraded).
- The JSON / SARIF / Markdown / GitHub-annotation / JUnit formatters
  (any output that breaks downstream parsers in ways that could mask
  a finding — including escaping bugs that let a crafted policy name
  or message forge or terminate a GitHub Actions workflow command).
- The `pgrls.testing` pytest plugin (any pattern where a passing test
  doesn't reflect actual RLS isolation).

## What's out of scope

- Vulnerabilities in PostgreSQL itself, in `pglast`, or in any other
  upstream dependency — report those to their respective projects.
- Vulnerabilities in the application *using* pgrls — if an RLS policy
  is broken, that's the schema's bug; pgrls's job is to *catch* such
  bugs and we ship a new rule rather than treat it as a pgrls
  vulnerability.

## Supported versions

The most recent minor release on PyPI receives security fixes. Earlier
0.x lines are not patched in place — upgrade is the supported path. A
major-version bump (1.0+) will introduce an explicit support window.
