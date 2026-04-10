using System;
using System.Security.Cryptography;
using System.Text;

namespace Jellyfin.Plugin.SSO.Security;

/// <summary>
/// Helper for generating PKCE (Proof Key for Code Exchange) parameters.
/// </summary>
public static class PkceHelper
{
    /// <summary>
    /// Generates a cryptographically random code verifier for PKCE.
    /// </summary>
    /// <returns>A Base64Url-encoded code verifier string (43 characters).</returns>
    public static string GenerateCodeVerifier()
    {
        return Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
    }

    /// <summary>
    /// Computes the S256 code challenge from a code verifier.
    /// </summary>
    /// <param name="codeVerifier">The code verifier.</param>
    /// <returns>The Base64Url-encoded SHA-256 hash of the verifier.</returns>
    public static string ComputeCodeChallenge(string codeVerifier)
    {
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
        return Base64UrlEncode(hash);
    }

    /// <summary>
    /// Generates a cryptographically random nonce for OIDC.
    /// </summary>
    /// <returns>A Base64Url-encoded nonce string.</returns>
    public static string GenerateNonce()
    {
        return Base64UrlEncode(RandomNumberGenerator.GetBytes(24));
    }

    private static string Base64UrlEncode(byte[] data)
    {
        return Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
