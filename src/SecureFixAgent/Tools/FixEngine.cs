using System.Text.RegularExpressions;
using SecureFixAgent.Models;

namespace SecureFixAgent.Tools;

/// <summary>
/// Tool: the deterministic remediation engine. Each rule knows how to rewrite one
/// vulnerable pattern into its secure equivalent and explain the change.
/// In a production deployment the LLM provider drafts the fix and this engine
/// acts as a verified library of known-good transformations; here the engine is
/// the source of truth so demo mode needs no API key.
/// </summary>
public sealed class FixEngine
{
    public FixResult Apply(Finding finding, string originalLine)
    {
        var trimmed = originalLine.Trim();
        return finding.RuleId.ToUpperInvariant() switch
        {
            "CWE-89" => FixSqlInjection(finding, originalLine),
            "CWE-798" => FixHardcodedSecret(finding, originalLine),
            "CWE-327" => FixWeakCrypto(finding, originalLine),
            "CWE-79" => FixXss(finding, originalLine),
            _ => new FixResult(finding, false, trimmed, trimmed,
                $"No automated rule is registered for {finding.RuleId} yet; the finding was triaged for manual review.",
                "Add a rule for this CWE to FixEngine, with a unit test, before enabling auto-fix.")
        };
    }

    private static FixResult FixSqlInjection(Finding f, string rawLine)
    {
        var line = rawLine.Trim();
        var indent = rawLine[..(rawLine.Length - rawLine.TrimStart().Length)];
        // Pattern: new SqlCommand("..." + var + "...", conn)
        var match = Regex.Match(line,
            @"new SqlCommand\(\s*""(?<sql>[^""]*?)""\s*\+\s*(?<v1>\w+)\s*\+\s*""(?<sql2>[^""]*?)""\s*,");
        if (!match.Success)
            return Unmatched(f, line, "SQL string concatenation");

        var sql = match.Groups["sql"].Value + "@p0" + match.Groups["sql2"].Value;
        var cmdVar = Regex.Match(line, @"var\s+(?<c>\w+)\s*=").Groups["c"].Value;
        if (string.IsNullOrEmpty(cmdVar)) cmdVar = "cmd";
        var fixedCode =
            $"{indent}var {cmdVar} = new SqlCommand(\"{sql}\", connection);\n" +
            $"{indent}{cmdVar}.Parameters.AddWithValue(\"@p0\", {match.Groups["v1"].Value});";
        return new FixResult(f, true, line, fixedCode,
            "The query text is now constant and the user input travels as a parameter, so the database can never interpret input as SQL.",
            "Never build SQL with string concatenation. Always use parameterized queries (SqlParameter / AddWithValue) or an ORM such as EF Core that parameterizes by default.");
    }

    private static FixResult FixHardcodedSecret(Finding f, string rawLine)
    {
        var line = rawLine.Trim();
        var indent = rawLine[..(rawLine.Length - rawLine.TrimStart().Length)];
        // Pattern: string dbPassword = "literal";
        var match = Regex.Match(line, @"(?<lhs>.*?=\s*)""[^""]*""\s*;");
        if (!match.Success)
            return Unmatched(f, line, "hardcoded secret");

        var varName = Regex.Match(line, @"(?<n>\w+)\s*=").Groups["n"].Value;
        var envName = Regex.Replace(varName, "(?<!^)([A-Z])", "_$1").ToUpperInvariant();
        var fixedCode =
            $"{indent}{match.Groups["lhs"].Value}Environment.GetEnvironmentVariable(\"{envName}\")" +
            $" ?? throw new InvalidOperationException(\"{envName} is not configured.\");";
        return new FixResult(f, true, line, fixedCode,
            "The secret is no longer in source control; it is injected at runtime from configuration and the app fails fast if it is missing.",
            "Load secrets from a vault or environment configuration (Azure Key Vault, AWS Secrets Manager, user-secrets in development). Rotate any secret that was ever committed.");
    }

    private static FixResult FixWeakCrypto(Finding f, string rawLine)
    {
        var line = rawLine.Trim();
        var indent = rawLine[..(rawLine.Length - rawLine.TrimStart().Length)];
        if (!line.Contains("MD5") && !line.Contains("SHA1"))
            return Unmatched(f, line, "weak cryptography");

        var fixedLine = indent + line.Replace("MD5.Create()", "SHA256.Create()")
                            .Replace("SHA1.Create()", "SHA256.Create()")
                            .Replace("new MD5CryptoServiceProvider()", "SHA256.Create()")
                            .Replace("new SHA1CryptoServiceProvider()", "SHA256.Create()");
        return new FixResult(f, true, line, fixedLine,
            "MD5 and SHA1 are broken for integrity and unsuitable for new code; SHA-256 is the current baseline.",
            "Use SHA-256 (or stronger) for hashing, and a password-hashing algorithm such as bcrypt/Argon2/PBKDF2 for credentials - never a fast general-purpose hash.");
    }

    private static FixResult FixXss(Finding f, string rawLine)
    {
        var line = rawLine.Trim();
        var indent = rawLine[..(rawLine.Length - rawLine.TrimStart().Length)];
        // Pattern: Response.Write(variable);
        var match = Regex.Match(line, @"Response\.Write\(\s*(?<v>[^)]+?)\s*\)\s*;");
        if (!match.Success)
            return Unmatched(f, line, "unencoded output");

        var fixedCode = $"{indent}Response.Write(System.Net.WebUtility.HtmlEncode({match.Groups["v"].Value}));";
        return new FixResult(f, true, line, fixedCode,
            "User-controlled text is HTML-encoded before it reaches the page, so injected markup renders as harmless text instead of executing.",
            "Encode all untrusted output for its context (HTML, attribute, JavaScript, URL). In Razor/Blazor this encoding is automatic - avoid raw-HTML helpers for user data.");
    }

    private static FixResult Unmatched(Finding f, string line, string pattern) =>
        new(f, false, line, line,
            $"The line was flagged as {pattern}, but it does not match the exact shape this rule rewrites automatically, so nothing was changed.",
            "Review manually, then extend the rule (and its tests) to cover this shape before re-running the agent.");
}
