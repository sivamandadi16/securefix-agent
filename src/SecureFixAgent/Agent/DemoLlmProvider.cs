using SecureFixAgent.Models;

namespace SecureFixAgent.Agent;

/// <summary>
/// Deterministic, offline planner used in demo mode. It maps each CWE to a
/// remediation strategy the FixEngine knows how to execute, so the full agent
/// loop runs with zero API keys - ideal for CI, demos and unit tests.
/// </summary>
public sealed class DemoLlmProvider : ILlmProvider
{
    public string Name => "Demo (deterministic, offline)";

    public Task<string> PlanAsync(Finding finding, string vulnerableLine, CancellationToken ct = default)
    {
        var plan = finding.RuleId.ToUpperInvariant() switch
        {
            "CWE-89" => "Parameterize the SQL command so input is bound as data, not executed as code.",
            "CWE-798" => "Remove the secret from source and load it from environment configuration, failing fast if absent.",
            "CWE-327" => "Replace the weak hash (MD5/SHA1) with SHA-256.",
            "CWE-79" => "HTML-encode untrusted output before writing it to the response.",
            _ => "No automated strategy for this rule; triage for manual review."
        };
        return Task.FromResult(plan);
    }
}
