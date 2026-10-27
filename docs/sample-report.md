# SecureFix Agent - Remediation Report

Generated: 2026-10-27 12:17:57 -05:00
Findings processed: 4 | Auto-fixed: 4 | Needs manual review: 0

## SF-001 - SQL Injection: string-concatenated query (CWE-89, Critical)

**File:** `UsersRepository.cs` line 11  
**Status:** Auto-fixed

**Before**
```csharp
var cmd = new SqlCommand("SELECT DisplayName FROM Users WHERE Id = " + userId + " AND IsActive = 1", connection);
```
**After**
```csharp
        var cmd = new SqlCommand("SELECT DisplayName FROM Users WHERE Id = @p0 AND IsActive = 1", connection);
        cmd.Parameters.AddWithValue("@p0", userId);
```
**Why this fix works:** The query text is now constant and the user input travels as a parameter, so the database can never interpret input as SQL.

**Secure coding guidance:** Never build SQL with string concatenation. Always use parameterized queries (SqlParameter / AddWithValue) or an ORM such as EF Core that parameterizes by default.

## SF-002 - Hardcoded password in source code (CWE-798, High)

**File:** `AuthConfig.cs` line 6  
**Status:** Auto-fixed

**Before**
```csharp
public static string DbPassword = "P@ssw0rd123!";
```
**After**
```csharp
    public static string DbPassword = Environment.GetEnvironmentVariable("DB_PASSWORD") ?? throw new InvalidOperationException("DB_PASSWORD is not configured.");
```
**Why this fix works:** The secret is no longer in source control; it is injected at runtime from configuration and the app fails fast if it is missing.

**Secure coding guidance:** Load secrets from a vault or environment configuration (Azure Key Vault, AWS Secrets Manager, user-secrets in development). Rotate any secret that was ever committed.

## SF-004 - Cross-site scripting: unencoded output (CWE-79, High)

**File:** `SearchController.cs` line 9  
**Status:** Auto-fixed

**Before**
```csharp
Response.Write(searchTerm);
```
**After**
```csharp
        Response.Write(System.Net.WebUtility.HtmlEncode(searchTerm));
```
**Why this fix works:** User-controlled text is HTML-encoded before it reaches the page, so injected markup renders as harmless text instead of executing.

**Secure coding guidance:** Encode all untrusted output for its context (HTML, attribute, JavaScript, URL). In Razor/Blazor this encoding is automatic - avoid raw-HTML helpers for user data.

## SF-003 - Use of a broken cryptographic algorithm (MD5) (CWE-327, Medium)

**File:** `CryptoHelper.cs` line 10  
**Status:** Auto-fixed

**Before**
```csharp
using var md5 = MD5.Create();
```
**After**
```csharp
        using var md5 = SHA256.Create();
```
**Why this fix works:** MD5 and SHA1 are broken for integrity and unsuitable for new code; SHA-256 is the current baseline.

**Secure coding guidance:** Use SHA-256 (or stronger) for hashing, and a password-hashing algorithm such as bcrypt/Argon2/PBKDF2 for credentials - never a fast general-purpose hash.

