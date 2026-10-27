namespace SecureFixAgent.Tools;

/// <summary>Tool: writes patched copies of source files (originals are never modified).</summary>
public static class PatchWriter
{
    public static string WritePatchedFile(string outputRoot, string relativePath,
        string[] originalLines, int lineNumber, string replacement)
    {
        var lines = (string[])originalLines.Clone();
        var replacementLines = replacement.Replace("\r\n", "\n").Split('\n');
        var patched = new List<string>();
        patched.AddRange(lines.Take(lineNumber - 1));
        patched.AddRange(replacementLines);
        patched.AddRange(lines.Skip(lineNumber));

        var destination = Path.Combine(outputRoot, "patched", relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        File.WriteAllLines(destination, patched);
        return destination;
    }
}
