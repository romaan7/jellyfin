using System.Text.Json.Serialization;

namespace Jellyfin.Plugin.SSO.Discovery;

/// <summary>
/// Represents the subset of an OpenID Connect discovery document that we need.
/// </summary>
public class OidcDiscoveryDocument
{
    /// <summary>
    /// Gets or sets the authorization endpoint.
    /// </summary>
    [JsonPropertyName("authorization_endpoint")]
    public string AuthorizationEndpoint { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the token endpoint.
    /// </summary>
    [JsonPropertyName("token_endpoint")]
    public string TokenEndpoint { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the userinfo endpoint.
    /// </summary>
    [JsonPropertyName("userinfo_endpoint")]
    public string? UserinfoEndpoint { get; set; }

    /// <summary>
    /// Gets or sets the JWKS URI.
    /// </summary>
    [JsonPropertyName("jwks_uri")]
    public string? JwksUri { get; set; }
}
