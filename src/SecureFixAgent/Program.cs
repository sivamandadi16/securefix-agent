using SecureFixAgent.Agent;

// SecureFix Agent - an agentic-AI demo that triages static-analysis findings,
// plans a remediation for each one, applies a deterministic secure fix,
// verifies the vulnerable pattern is gone, and writes a Markdown report.
//
// Usage:
//   dotnet run --project src/SecureFixAgent -- \
//     --findings samples/findings.json --source samples/vulnerable --out output [--provider demo|azure]
//
// Demo mode (default) needs no API key. Azure mode uses AZURE_OPENAI_* env vars.

string GetArg(string name, string fallback)
{
    var i = Array.IndexOf(args, name);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : fallback;
}

var findings = GetArg("--findings", "samples/findings.json");
var source = GetArg("--source", "samples/vulnerable");
var output = GetArg("--out", "output");
var provider = GetArg("--provider", "demo").ToLowerInvariant();

Console.WriteLine("=== SecureFix Agent ===");
ILlmProvider planner = provider switch
{
    "demo" => new DemoLlmProvider(),
    "azure" => new AzureOpenAiProvider(),
    _ => throw new ArgumentException($"Unknown provider '{provider}'. Use 'demo' or 'azure'.")
};

var agent = new SecureFixAgent.Agent.SecureFixAgent(planner);
var results = await agent.RunAsync(findings, source, output);

return results.All(r => r.Fixed) ? 0 : 2; // non-zero if anything needs manual review
