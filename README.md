# SecureFix Agent 🤖🔐

**An agentic AI assistant (.NET 8) that remediates static-analysis security findings.**

Give it a findings report (Veracode / CodeQL style JSON) and it works through
each finding like an engineer would: it reads the vulnerable code, plans a
fix, applies a verified secure rewrite, checks the vulnerability is really
gone, and writes a human-readable remediation report with before/after diffs
and secure-coding guidance.

![.NET 8](https://img.shields.io/badge/.NET-8.0-512BD4) ![C#](https://img.shields.io/badge/C%23-12-239120) ![License: MIT](https://img.shields.io/badge/License-MIT-green)

## Why this exists

Security scanners are good at *finding* problems and silent about *fixing*
them. Teams sit on backlogs of hundreds of findings. SecureFix Agent is a
clean-room demo of the remediation pattern I work with professionally:
**an LLM plans, deterministic verified code acts, and a human reviews the
diff** - so automation is fast *and* auditable.

## The agent loop

For every finding (highest severity first):

1. **OBSERVE** - load the finding and read the exact vulnerable line
2. **PLAN** - ask the LLM provider for a one-sentence remediation plan
3. **ACT** - apply the matching rule from the deterministic `FixEngine` and
   write a *patched copy* (originals are never modified)
4. **VERIFY** - re-read the patched file and assert the vulnerable pattern
   is gone
5. **REPORT** - emit `remediation-report.md` with before/after, the reason
   the fix works, and secure-coding guidance

## Rules included

| Rule | Finding | Fix |
| --- | --- | --- |
| CWE-89 | SQL injection (string-concatenated query) | Parameterized query (`Parameters.AddWithValue`) |
| CWE-798 | Hardcoded password | Load from environment configuration, fail fast if missing |
| CWE-327 | Weak crypto (MD5 / SHA1) | SHA-256 |
| CWE-79 | XSS (unencoded output) | `WebUtility.HtmlEncode` |

Unknown rules are **triaged for manual review, never guessed at** - and the
process exits `2` so CI can tell the difference.

## Quick start

No API key needed - demo mode is fully offline and deterministic:

```bash
dotnet run --project src/SecureFixAgent -- \
  --findings samples/findings.json \
  --source    samples/vulnerable \
  --out       output
```

Then open `output/remediation-report.md` and the patched files in
`output/patched/`. A committed example report is in
[`docs/sample-report.md`](docs/sample-report.md).

### Use Azure OpenAI as the planner

```bash
export AZURE_OPENAI_ENDPOINT="https://<resource>.openai.azure.com"
export AZURE_OPENAI_API_KEY="<key>"
export AZURE_OPENAI_DEPLOYMENT="gpt-4o-mini"

dotnet run --project src/SecureFixAgent -- --provider azure \
  --findings samples/findings.json --source samples/vulnerable --out output
```

The provider only *plans*; the deterministic engine remains the authority
that rewrites code. See [`docs/architecture.md`](docs/architecture.md).

## Tests

```bash
dotnet test
```

xUnit tests cover every fix rule, the safe unknown-rule default, and
severity ordering.

## Project layout

```
src/SecureFixAgent/
  Program.cs            CLI entry point + argument handling
  Agent/                the agent loop + LLM providers (demo / Azure OpenAI)
  Tools/                FindingLoader, CodeReader, FixEngine, PatchWriter, ReportWriter
  Models/               Finding, FixResult, AgentStep
samples/                findings.json + four intentionally vulnerable files
tests/                  xUnit test project
docs/                   architecture notes + a sample generated report
```

> ⚠️ The files under `samples/vulnerable/` are **intentionally insecure**
> teaching examples. Do not copy them into real projects.

## About

Built by **Siva Mandadi** - Senior .NET Full Stack Developer (C# / .NET Core,
React & Angular, Azure & AWS, Agentic AI). This project is an original,
clean-room implementation created for demonstration; it contains no code
from any employer.
