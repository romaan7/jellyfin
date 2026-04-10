using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO.Configuration;

/// <summary>
/// Configuration for Google OAuth2 authentication.
/// </summary>
public class GoogleOAuthConfig
{
    /// <summary>
    /// Gets or sets a value indicating whether Google OAuth is enabled.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Gets or sets the Google OAuth client ID.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the Google OAuth client secret.
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the allowed email domains (comma-separated). Empty allows all domains.
    /// </summary>
    public string AllowedDomains { get; set; } = string.Empty;

    /// <summary>
    /// Gets the role mappings for this provider.
    /// </summary>
    public IList<RoleMapping> RoleMappings { get; } = new List<RoleMapping>();
}
