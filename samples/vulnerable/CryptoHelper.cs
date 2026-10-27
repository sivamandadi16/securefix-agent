using System.Security.Cryptography;
using System.Text;

namespace DemoApp.Security;

public static class CryptoHelper
{
    public static string Fingerprint(string value)
    {
        using var md5 = MD5.Create();
        var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(hash);
    }
}
