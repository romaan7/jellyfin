using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO.Configuration;

/// <summary>
/// Configuration for a generic OpenID Connect provider.
/// </summary>
public class GenericOIDCConfig
{
    /// <summary>
    /// Gets or sets a value indicating whether the generic OIDC provider is enabled.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Gets or sets the display name for this provider.
    /// </summary>
    public string DisplayName { get; set; } = "OIDC";

    /// <summary>
    /// Gets or sets the authorization endpoint URL.
    /// </summary>
    public string AuthorizationEndpoint { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the token endpoint URL.
    /// </summary>
    public string TokenEndpoint { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the user info endpoint URL.
    /// </summary>
    public string UserInfoEndpoint { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the client ID.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the client secret.
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the scopes to request (space-separated).
    /// </summary>
    public string Scopes { get; set; } = "openid profile email";

    /// <summary>
    /// Gets or sets the claim name used for the user's unique ID.
    /// </summary>
    public string UserIdClaim { get; set; } = "sub";

    /// <summary>
    /// Gets or sets the claim name used for the user's username.
    /// </summary>
    public string UsernameClaim { get; set; } = "preferred_username";

    /// <summary>
    /// Gets or sets the allowed email domains (comma-separated). Empty allows all domains.
    /// </summary>
    public string AllowedDomains { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets a custom icon URL for the login button.
    /// </summary>
    public string? IconUrl { get; set; }

    /// <summary>
    /// Gets or sets the OIDC issuer URL for auto-discovery.
    /// When set, authorization, token, and userinfo endpoints are discovered automatically.
    /// </summary>
    public string IssuerUrl { get; set; } = string.Empty;

    /// <summary>
    /// Gets the role mappings for this provider.
    /// </summary>
    public IList<RoleMapping> RoleMappings { get; } = new List<RoleMapping>();
}
