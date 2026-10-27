using SecureFixAgent.Models;
using SecureFixAgent.Tools;
using Xunit;

namespace SecureFixAgent.Tests;

public class FixEngineTests
{
    private readonly FixEngine _engine = new();

    private static Finding F(string ruleId) =>
        new("T-1", ruleId, "test", "High", "Sample.cs", 1, "test finding");

    [Fact]
    public void SqlInjection_BecomesParameterizedQuery()
    {
        var line = "var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Id = \" + userId + \" AND Active = 1\", connection);";
        var result = _engine.Apply(F("CWE-89"), line);

        Assert.True(result.Fixed);
        Assert.Contains("Parameters.AddWithValue(\"@p0\", userId)", result.FixedCode);
        Assert.DoesNotContain("+ userId +", result.FixedCode);
    }

    [Fact]
    public void HardcodedSecret_MovesToEnvironment()
    {
        var line = "public static string DbPassword = \"P@ssw0rd123!\";";
        var result = _engine.Apply(F("CWE-798"), line);

        Assert.True(result.Fixed);
        Assert.Contains("Environment.GetEnvironmentVariable(\"DB_PASSWORD\")", result.FixedCode);
        Assert.DoesNotContain("P@ssw0rd123!", result.FixedCode);
    }

    [Fact]
    public void WeakCrypto_Md5_BecomesSha256()
    {
        var line = "using var md5 = MD5.Create();";
        var result = _engine.Apply(F("CWE-327"), line);

        Assert.True(result.Fixed);
        Assert.Contains("SHA256.Create()", result.FixedCode);
        Assert.DoesNotContain("MD5", result.FixedCode);
    }

    [Fact]
    public void Xss_Output_GetsHtmlEncoded()
    {
        var line = "Response.Write(searchTerm);";
        var result = _engine.Apply(F("CWE-79"), line);

        Assert.True(result.Fixed);
        Assert.Contains("WebUtility.HtmlEncode(searchTerm)", result.FixedCode);
    }

    [Fact]
    public void UnknownRule_IsFlaggedForManualReview_NotChanged()
    {
        var line = "var x = 1;";
        var result = _engine.Apply(F("CWE-9999"), line);

        Assert.False(result.Fixed);
        Assert.Equal(line, result.FixedCode);
    }

    [Fact]
    public void SeverityRanking_OrdersCriticalFirst()
    {
        Assert.True(FindingLoader.SeverityRank("Critical") > FindingLoader.SeverityRank("High"));
        Assert.True(FindingLoader.SeverityRank("High") > FindingLoader.SeverityRank("Low"));
    }
}
