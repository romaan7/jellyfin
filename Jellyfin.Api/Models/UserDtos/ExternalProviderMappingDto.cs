using System;

namespace Jellyfin.Api.Models.UserDtos;

/// <summary>
/// DTO representing a user's external authentication provider mapping.
/// </summary>
public class ExternalProviderMappingDto
{
    /// <summary>
    /// Gets or sets the Jellyfin user ID.
    /// </summary>
    public Guid UserId { get; set; }

    /// <summary>
    /// Gets or sets the external provider name.
    /// </summary>
    public required string ProviderName { get; set; }

    /// <summary>
    /// Gets or sets the date the mapping was created.
    /// </summary>
    public DateTime DateCreated { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether this user must use SSO login.
    /// </summary>
    public bool ForceExternalAuth { get; set; }
}
