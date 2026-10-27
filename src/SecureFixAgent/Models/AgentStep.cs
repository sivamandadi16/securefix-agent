namespace SecureFixAgent.Models;

/// <summary>One step in the agent's observe-plan-act-verify loop, for the run log.</summary>
public sealed record AgentStep(string Phase, string Message)
{
    public override string ToString() => $"[{Phase,-7}] {Message}";
}
