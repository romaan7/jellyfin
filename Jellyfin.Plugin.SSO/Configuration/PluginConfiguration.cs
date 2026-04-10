using MediaBrowser.Model.Plugins;

namespace Jellyfin.Plugin.SSO.Configuration;

/// <summary>
/// Configuration for the SSO plugin.
/// </summary>
public class PluginConfiguration : BasePluginConfiguration
{
    /// <summary>
    /// Gets or sets the Google OAuth configuration.
    /// </summary>
    public GoogleOAuthConfig GoogleOAuth { get; set; } = new();

    /// <summary>
    /// Gets or sets the generic OIDC provider configuration.
    /// </summary>
    public GenericOIDCConfig GenericOIDC { get; set; } = new();
}
