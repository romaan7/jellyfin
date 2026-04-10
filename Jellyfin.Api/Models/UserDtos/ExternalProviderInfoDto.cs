namespace Jellyfin.Api.Models.UserDtos;

/// <summary>
/// Information about an available external authentication provider.
/// </summary>
public class ExternalProviderInfoDto
{
    /// <summary>
    /// Gets or sets the provider name.
    /// </summary>
    public required string Name { get; set; }

    /// <summary>
    /// Gets or sets the icon type (e.g., "google", "oidc").
    /// </summary>
    public string? IconType { get; set; }

    /// <summary>
    /// Gets or sets a custom icon URL for the provider.
    /// </summary>
    public string? IconUrl { get; set; }
}
