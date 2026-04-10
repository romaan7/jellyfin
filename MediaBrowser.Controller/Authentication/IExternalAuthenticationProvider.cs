using System.Collections.Generic;
using System.Threading.Tasks;

namespace MediaBrowser.Controller.Authentication;

/// <summary>
/// Interface for external authentication providers (OAuth2, OIDC).
/// </summary>
public interface IExternalAuthenticationProvider
{
    /// <summary>
    /// Gets the display name of this provider.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Gets a value indicating whether this provider is currently enabled.
    /// </summary>
    bool IsEnabled { get; }

    /// <summary>
    /// Gets the icon type for this provider (e.g., "google", "oidc").
    /// </summary>
    string? IconType => null;

    /// <summary>
    /// Gets the custom icon URL for this provider.
    /// </summary>
    string? IconUrl => null;

    /// <summary>
    /// Gets the role mappings configured for this provider.
    /// </summary>
    /// <returns>The list of role mappings, or an empty list if none configured.</returns>
    IReadOnlyList<ExternalRoleMapping> RoleMappings => [];

    /// <summary>
    /// Initiates an external authentication flow by generating an authorization URL.
    /// </summary>
    /// <param name="callbackUrl">The callback URL to redirect to after authentication.</param>
    /// <param name="state">The CSRF state token.</param>
    /// <param name="codeChallenge">Optional PKCE code challenge (S256).</param>
    /// <returns>The initiation result containing the authorization URL.</returns>
    Task<ExternalAuthInitiationResult> InitiateAuthentication(string callbackUrl, string state, string? codeChallenge = null);

    /// <summary>
    /// Completes the authentication flow by exchanging an authorization code for tokens.
    /// </summary>
    /// <param name="code">The authorization code from the provider.</param>
    /// <param name="state">The CSRF state token to validate.</param>
    /// <param name="callbackUrl">The callback URL used during initiation.</param>
    /// <param name="codeVerifier">Optional PKCE code verifier.</param>
    /// <returns>The token result from the provider.</returns>
    Task<ExternalAuthTokenResult> CompleteAuthentication(string code, string state, string callbackUrl, string? codeVerifier = null);

    /// <summary>
    /// Refreshes an access token using a refresh token.
    /// </summary>
    /// <param name="refreshToken">The refresh token.</param>
    /// <returns>New token result, or null if refresh is not supported.</returns>
    Task<ExternalAuthTokenResult?> RefreshAccessToken(string refreshToken) => Task.FromResult<ExternalAuthTokenResult?>(null);

    /// <summary>
    /// Retrieves user information from the external provider using an access token.
    /// </summary>
    /// <param name="accessToken">The access token from the provider.</param>
    /// <returns>The external user information.</returns>
    Task<ExternalUserInfo> GetUserInfo(string accessToken);
}
