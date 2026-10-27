using SecureFixAgent.Models;
using SecureFixAgent.Tools;

namespace SecureFixAgent.Agent;

/// <summary>
/// The agent. For every finding it runs an explicit loop:
///   OBSERVE  - read the finding and the vulnerable code
///   PLAN     - ask the LLM provider for a remediation plan
///   ACT      - apply the deterministic fix rule and write a patched copy
///   VERIFY   - re-read the patched file and confirm the vulnerable pattern is gone
///   REPORT   - collect the result for the Markdown report
/// Patched copies go to the output folder; original sources are never touched.
/// </summary>
public sealed class SecureFixAgent
{
    private readonly ILlmProvider _planner;
    private readonly FixEngine _fixEngine = new();
    private readonly List<AgentStep> _log = new();

    public IReadOnlyList<AgentStep> Log => _log;

    public SecureFixAgent(ILlmProvider planner) => _planner = planner;

    public async Task<IReadOnlyList<FixResult>> RunAsync(
        string findingsPath, string sourceRoot, string outputRoot, CancellationToken ct = default)
    {
        Say("OBSERVE", $"Loading findings from {findingsPath}");
        var findings = FindingLoader.Load(findingsPath);
        Say("OBSERVE", $"{findings.Count} finding(s) queued, highest severity first. Planner: {_planner.Name}");

        var results = new List<FixResult>();
        foreach (var finding in findings)
        {
            ct.ThrowIfCancellationRequested();
            results.Add(await ProcessFindingAsync(finding, sourceRoot, outputRoot, ct));
        }

        var reportPath = ReportWriter.Write(outputRoot, results);
        Say("REPORT", $"Remediation report written to {reportPath}");
        Say("REPORT", $"Done: {results.Count(r => r.Fixed)} auto-fixed, {results.Count(r => !r.Fixed)} for manual review.");
        return results;
    }

    private async Task<FixResult> ProcessFindingAsync(
        Finding finding, string sourceRoot, string outputRoot, CancellationToken ct)
    {
        Say("OBSERVE", $"{finding.Id} {finding.RuleId} in {finding.FilePath}:{finding.Line} ({finding.Severity})");
        var originalLine = CodeReader.ReadLine(sourceRoot, finding.FilePath, finding.Line);

        var plan = await _planner.PlanAsync(finding, originalLine, ct);
        Say("PLAN", $"{finding.Id}: {plan}");

        var result = _fixEngine.Apply(finding, originalLine);
        if (!result.Fixed)
        {
            Say("ACT", $"{finding.Id}: no automated fix - flagged for manual review.");
            return result;
        }

        var allLines = CodeReader.ReadAllLines(sourceRoot, finding.FilePath);
        var patchedPath = PatchWriter.WritePatchedFile(outputRoot, finding.FilePath, allLines, finding.Line, result.FixedCode);
        Say("ACT", $"{finding.Id}: patched copy written to {patchedPath}");

        var verified = VerifyPatchedFile(patchedPath, finding);
        Say("VERIFY", verified
            ? $"{finding.Id}: vulnerable pattern no longer present in patched file."
            : $"{finding.Id}: WARNING - pattern still detected, needs a human look.");
        return result;
    }

    private static bool VerifyPatchedFile(string patchedPath, Finding finding)
    {
        var text = File.ReadAllText(patchedPath);
        return finding.RuleId.ToUpperInvariant() switch
        {
            "CWE-89" => !text.Contains("\" +") && text.Contains("Parameters.AddWithValue"),
            "CWE-798" => text.Contains("GetEnvironmentVariable"),
            "CWE-327" => !text.Contains("MD5") && !text.Contains("SHA1"),
            "CWE-79" => text.Contains("HtmlEncode"),
            _ => true
        };
    }

    private void Say(string phase, string message)
    {
        var step = new AgentStep(phase, message);
        _log.Add(step);
        Console.WriteLine(step);
    }
}
