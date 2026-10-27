using System.Text.Json;
using SecureFixAgent.Models;

namespace SecureFixAgent.Tools;

/// <summary>Tool: loads static-analysis findings from a JSON report.</summary>
public static class FindingLoader
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public static IReadOnlyList<Finding> Load(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException($"Findings file not found: {path}", path);

        var json = File.ReadAllText(path);
        var findings = JsonSerializer.Deserialize<List<Finding>>(json, Options)
                       ?? throw new InvalidOperationException("Findings file contained no findings.");
        return findings.OrderByDescending(f => SeverityRank(f.Severity)).ToList();
    }

    public static int SeverityRank(string severity) => severity.ToLowerInvariant() switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0
    };
}
