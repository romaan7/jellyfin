namespace Jellyfin.Plugin.SSO.Configuration;

/// <summary>
/// Defines a mapping from an external provider claim to a Jellyfin permission.
/// </summary>
public class RoleMapping
{
    /// <summary>
    /// Gets or sets the claim name to match (e.g. "groups", "roles").
    /// </summary>
    public string ClaimName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the claim value to match (e.g. "jellyfin-admin").
    /// For array claims, matches if the value is contained in the array.
    /// </summary>
    public string ClaimValue { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the Jellyfin permission name (e.g. "IsAdministrator").
    /// Must correspond to a <see cref="Jellyfin.Database.Implementations.Enums.PermissionKind"/> enum value.
    /// </summary>
    public string Permission { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets a value indicating whether to grant (true) or deny (false) the permission when the claim matches.
    /// </summary>
    public bool Grant { get; set; } = true;
}
