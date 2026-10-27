# Architecture

SecureFix Agent is a small, explicit agent loop - no framework magic - so every
step can be read, tested, and explained.

```
 findings.json ──► FindingLoader (tool)
                        │
                        ▼
              ┌──────────────────────┐
              │   SecureFixAgent     │   for each finding (severity order):
              │                      │
              │  OBSERVE  read the vulnerable line (CodeReader tool)
              │  PLAN     ask the ILlmProvider for a remediation plan
              │  ACT      FixEngine rewrites the line; PatchWriter
              │           writes a patched COPY (originals untouched)
              │  VERIFY   re-read the patched file; assert the
              │           vulnerable pattern is gone
              │  REPORT   collect before/after + explanation
              └──────────────────────┘
                        │
                        ▼
        output/remediation-report.md  +  output/patched/*.cs
```

## Design decisions

- **The LLM plans, deterministic code acts.** `ILlmProvider` produces a
  one-sentence plan. The actual rewrite comes from `FixEngine`, a library of
  tested transformations - so a fix is never applied just because a model
  suggested it. This mirrors how production remediation pipelines work:
  the model proposes, verified code disposes.
- **Provider swap without touching the loop.** `DemoLlmProvider` is fully
  offline and deterministic (CI, demos, tests). `AzureOpenAiProvider` calls
  Azure OpenAI chat completions with raw `HttpClient` - no vendor SDK lock-in.
- **Patched copies, never in-place edits.** The agent writes to
  `output/patched/`, so a human reviews a diff before anything lands.
- **Verify is a real check, not a log line.** Each rule has a post-condition
  (e.g. CWE-89: the patched file contains `Parameters.AddWithValue` and no
  string-concatenated SQL) and the agent reports if it fails.
- **Exit code is CI-friendly:** `0` when every finding was auto-fixed, `2`
  when anything was left for manual review.

## Extending it

Add a rule: implement a `Fix*` method in `FixEngine`, add the CWE to the
`DemoLlmProvider` plan map, add the post-condition to `VerifyPatchedFile`,
and write a unit test. The unknown-rule test shows the safe default -
unrecognized findings are triaged, never guessed at.
