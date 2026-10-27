namespace SecureFixAgent.Tools;

/// <summary>Tool: reads the source snippet around a finding so the agent can work on real code.</summary>
public static class CodeReader
{
    public static string[] ReadAllLines(string sourceRoot, string relativePath)
    {
        var full = Path.Combine(sourceRoot, relativePath);
        if (!File.Exists(full))
            throw new FileNotFoundException($"Source file not found: {full}", full);
        return File.ReadAllLines(full);
    }

    /// <summary>Returns the exact line the finding points at (1-based).</summary>
    public static string ReadLine(string sourceRoot, string relativePath, int line)
    {
        var lines = ReadAllLines(sourceRoot, relativePath);
        if (line < 1 || line > lines.Length)
            throw new ArgumentOutOfRangeException(nameof(line),
                $"Line {line} is outside {relativePath} (1..{lines.Length}).");
        return lines[line - 1];
    }
}
