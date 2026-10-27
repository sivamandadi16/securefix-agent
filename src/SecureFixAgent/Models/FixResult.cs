namespace SecureFixAgent.Models;

/// <summary>The outcome of the agent working on one finding.</summary>
public sealed record FixResult(
    Finding Finding,
    bool Fixed,
    string OriginalCode,
    string FixedCode,
    string Explanation,
    string SecureCodingGuidance);
