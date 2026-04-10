using System.Collections.Generic;

namespace MediaBrowser.Controller.Authentication;

/// <summary>
/// User information returned from an external authentication provider.
/// </summary>
public class ExternalUserInfo
{
    /// <summary>
    /// Gets or sets the unique user ID from the provider.
    /// </summary>
    public required string ProviderId { get; set; }

    /// <summary>
    /// Gets or sets the user's email address.
    /// </summary>
    public string? Email { get; set; }

    /// <summary>
    /// Gets or sets the preferred username.
    /// </summary>
    public required string Username { get; set; }

    /// <summary>
    /// Gets or sets the display name.
    /// </summary>
    public string? DisplayName { get; set; }

    /// <summary>
    /// Gets or sets additional claims from the provider.
    /// </summary>
    public Dictionary<string, string> Claims { get; set; } = new();
}
