namespace Jellyfin.Api.Models.UserDtos;

/// <summary>
/// The response from initiating an external authentication flow.
/// </summary>
public class ExternalAuthInitiationDto
{
    /// <summary>
    /// Gets or sets the authorization URL to redirect the user to.
    /// </summary>
    public required string AuthorizationUrl { get; set; }
}
