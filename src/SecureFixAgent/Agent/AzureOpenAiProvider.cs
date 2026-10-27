using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using SecureFixAgent.Models;

namespace SecureFixAgent.Agent;

/// <summary>
/// Planner backed by Azure OpenAI chat completions. Requires:
///   AZURE_OPENAI_ENDPOINT    e.g. https://my-resource.openai.azure.com
///   AZURE_OPENAI_API_KEY     key for the resource
///   AZURE_OPENAI_DEPLOYMENT  deployed model name, e.g. gpt-4o-mini
/// The provider only plans; the deterministic FixEngine remains the authority
/// that rewrites code, which keeps production fixes auditable and testable.
/// </summary>
public sealed class AzureOpenAiProvider : ILlmProvider
{
    private static readonly HttpClient Http = new();
    private readonly string _endpoint, _apiKey, _deployment;

    public string Name => $"Azure OpenAI ({_deployment})";

    public AzureOpenAiProvider()
    {
        _endpoint = Require("AZURE_OPENAI_ENDPOINT").TrimEnd('/');
        _apiKey = Require("AZURE_OPENAI_API_KEY");
        _deployment = Require("AZURE_OPENAI_DEPLOYMENT");
    }

    public async Task<string> PlanAsync(Finding finding, string vulnerableLine, CancellationToken ct = default)
    {
        var url = $"{_endpoint}/openai/deployments/{_deployment}/chat/completions?api-version=2024-08-01-preview";
        var payload = new
        {
            messages = new object[]
            {
                new { role = "system", content = "You are a senior application-security engineer. Reply with a single-sentence remediation plan, no code." },
                new { role = "user", content = $"Finding {finding.RuleId} ({finding.Title}) in {finding.FilePath} line {finding.Line}: {finding.Description}\nVulnerable line: {vulnerableLine}\nWhat is the remediation plan?" }
            },
            temperature = 0.1,
            max_tokens = 120
        };

        using var req = new HttpRequestMessage(HttpMethod.Post, url);
        req.Headers.Add("api-key", _apiKey);
        req.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        using var resp = await Http.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        return doc.RootElement.GetProperty("choices")[0].GetProperty("message").GetProperty("content")
                  .GetString()?.Trim() ?? "(no plan returned)";
    }

    private static string Require(string name) =>
        Environment.GetEnvironmentVariable(name)
        ?? throw new InvalidOperationException(
            $"Environment variable {name} is not set. Set the AZURE_OPENAI_* variables or run with --provider demo.");
}
