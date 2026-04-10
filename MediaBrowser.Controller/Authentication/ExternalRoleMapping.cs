namespace MediaBrowser.Controller.Authentication;

/// <summary>
/// Defines a mapping from an external provider claim to a Jellyfin permission.
/// </summary>
public class ExternalRoleMapping
{
    /// <summary>
    /// Gets or sets the claim name to match (e.g. "groups", "roles").
    /// </summary>
    public string ClaimName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the claim value to match (e.g. "jellyfin-admin").
    /// </summary>
    public string ClaimValue { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the Jellyfin permission name (e.g. "IsAdministrator").
    /// </summary>
    public string Permission { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets a value indicating whether to grant (true) or deny (false) the permission.
    /// </summary>
    public bool Grant { get; set; } = true;
}
