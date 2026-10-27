using SecureFixAgent.Models;

namespace SecureFixAgent.Agent;

/// <summary>
/// The planner brain of the agent. Implementations decide, for each finding,
/// what the agent should do. Swap providers without touching the agent loop.
/// </summary>
public interface ILlmProvider
{
    string Name { get; }

    /// <summary>Returns a one-line plan for this finding.</summary>
    Task<string> PlanAsync(Finding finding, string vulnerableLine, CancellationToken ct = default);
}
