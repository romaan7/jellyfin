namespace MediaBrowser.Controller.Authentication;

/// <summary>
/// The token result from completing an external authentication flow.
/// </summary>
public class ExternalAuthTokenResult
{
    /// <summary>
    /// Gets or sets the access token.
    /// </summary>
    public required string AccessToken { get; set; }

    /// <summary>
    /// Gets or sets the refresh token.
    /// </summary>
    public string? RefreshToken { get; set; }

    /// <summary>
    /// Gets or sets the ID token (for OIDC providers).
    /// </summary>
    public string? IdToken { get; set; }

    /// <summary>
    /// Gets or sets the token expiry in seconds.
    /// </summary>
    public int ExpiresIn { get; set; }
}
