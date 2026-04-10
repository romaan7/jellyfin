using System.ComponentModel.DataAnnotations;

namespace Jellyfin.Api.Models.UserDtos;

/// <summary>
/// The external auth initiation request body.
/// </summary>
public class ExternalAuthInitiateRequest
{
    /// <summary>
    /// Gets or sets the callback URL for the OAuth redirect.
    /// </summary>
    [Required]
    public required string CallbackUrl { get; set; }

    /// <summary>
    /// Gets or sets the client device ID.
    /// </summary>
    public string? DeviceId { get; set; }

    /// <summary>
    /// Gets or sets the client device name.
    /// </summary>
    public string? DeviceName { get; set; }

    /// <summary>
    /// Gets or sets the client application name.
    /// </summary>
    public string? AppName { get; set; }

    /// <summary>
    /// Gets or sets the client application version.
    /// </summary>
    public string? AppVersion { get; set; }
}
