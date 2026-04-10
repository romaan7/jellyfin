namespace MediaBrowser.Controller.Authentication;

/// <summary>
/// The result of initiating an external authentication flow.
/// </summary>
public class ExternalAuthInitiationResult
{
    /// <summary>
    /// Gets or sets the authorization URL to redirect the user to.
    /// </summary>
    public required string AuthorizationUrl { get; set; }

    /// <summary>
    /// Gets or sets the CSRF state token.
    /// </summary>
    public required string State { get; set; }
}
