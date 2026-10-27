using SecureFixAgent.Models;

namespace SecureFixAgent.Tools;

/// <summary>Tool: writes the human-readable remediation report as Markdown.</summary>
public static class ReportWriter
{
    public static string Write(string outputRoot, IReadOnlyList<FixResult> results)
    {
        Directory.CreateDirectory(outputRoot);
        var path = Path.Combine(outputRoot, "remediation-report.md");
        using var w = new StreamWriter(path);

        w.WriteLine("# SecureFix Agent - Remediation Report");
        w.WriteLine();
        w.WriteLine($"Generated: {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
        w.WriteLine($"Findings processed: {results.Count} | Auto-fixed: {results.Count(r => r.Fixed)} | Needs manual review: {results.Count(r => !r.Fixed)}");
        w.WriteLine();

        foreach (var r in results)
        {
            w.WriteLine($"## {r.Finding.Id} - {r.Finding.Title} ({r.Finding.RuleId}, {r.Finding.Severity})");
            w.WriteLine();
            w.WriteLine($"**File:** `{r.Finding.FilePath}` line {r.Finding.Line}  ");
            w.WriteLine($"**Status:** {(r.Fixed ? "Auto-fixed" : "Manual review required")}");
            w.WriteLine();
            w.WriteLine("**Before**");
            w.WriteLine("```csharp");
            w.WriteLine(r.OriginalCode);
            w.WriteLine("```");
            if (r.Fixed)
            {
                w.WriteLine("**After**");
                w.WriteLine("```csharp");
                w.WriteLine(r.FixedCode);
                w.WriteLine("```");
            }
            w.WriteLine($"**Why this fix works:** {r.Explanation}");
            w.WriteLine();
            w.WriteLine($"**Secure coding guidance:** {r.SecureCodingGuidance}");
            w.WriteLine();
        }
        return path;
    }
}
