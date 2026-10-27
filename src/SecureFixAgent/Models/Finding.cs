namespace SecureFixAgent.Models;

/// <summary>One static-analysis finding (Veracode / CodeQL style) to remediate.</summary>
public sealed record Finding(
    string Id,
    string RuleId,        // e.g. CWE-89
    string Title,
    string Severity,      // Critical | High | Medium | Low
    string FilePath,
    int Line,
    string Description);
