using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Jellyfin.Api.Extensions;
using Jellyfin.Api.Models.UserDtos;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Extensions.Json;
using MediaBrowser.Common.Api;
using MediaBrowser.Common.Extensions;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Api.Controllers;

/// <summary>
/// Controller for external (SSO) authentication flows.
/// </summary>
[Route("Auth/SSO")]
public class ExternalAuthController : BaseJellyfinApiController
{
    private readonly IEnumerable<IExternalAuthenticationProvider> _externalProviders;
    private readonly IExternalAuthService _externalAuthService;
    private readonly IUserManager _userManager;
    private readonly ISessionManager _sessionManager;
    private readonly IServerConfigurationManager _config;
    private readonly ILogger<ExternalAuthController> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="ExternalAuthController"/> class.
    /// </summary>
    /// <param name="externalProviders">The registered external authentication providers.</param>
    /// <param name="externalAuthService">The external auth service.</param>
    /// <param name="userManager">The user manager.</param>
    /// <param name="sessionManager">The session manager.</param>
    /// <param name="config">The server configuration manager.</param>
    /// <param name="logger">The logger.</param>
    public ExternalAuthController(
        IEnumerable<IExternalAuthenticationProvider> externalProviders,
        IExternalAuthService externalAuthService,
        IUserManager userManager,
        ISessionManager sessionManager,
        IServerConfigurationManager config,
        ILogger<ExternalAuthController> logger)
    {
        _externalProviders = externalProviders;
        _externalAuthService = externalAuthService;
        _userManager = userManager;
        _sessionManager = sessionManager;
        _config = config;
        _logger = logger;
    }

    /// <summary>
    /// Gets the list of available external authentication providers.
    /// </summary>
    /// <response code="200">Available providers returned.</response>
    /// <returns>A list of available external provider info.</returns>
    [HttpGet("Providers")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public ActionResult<IEnumerable<ExternalProviderInfoDto>> GetProviders()
    {
        var providers = _externalProviders
            .Where(p => p.IsEnabled)
            .Select(p => new ExternalProviderInfoDto
            {
                Name = p.Name,
                IconType = p.IconType,
                IconUrl = p.IconUrl
            });

        return Ok(providers);
    }

    /// <summary>
    /// Gets all external authentication provider mappings for all users.
    /// </summary>
    /// <response code="200">Mappings returned.</response>
    /// <returns>A list of external provider mappings.</returns>
    [HttpGet("Mappings")]
    [Authorize(Policy = Policies.RequiresElevation)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult<IEnumerable<ExternalProviderMappingDto>>> GetMappings()
    {
        var mappings = await _externalAuthService.GetAllMappingsAsync().ConfigureAwait(false);

        var dtos = mappings.Select(m => new ExternalProviderMappingDto
        {
            UserId = m.UserId,
            ProviderName = m.ProviderName,
            DateCreated = m.DateCreated,
            ForceExternalAuth = m.ForceExternalAuth
        });

        return Ok(dtos);
    }

    /// <summary>
    /// Gets external authentication provider mappings for a specific user.
    /// </summary>
    /// <param name="userId">The user ID.</param>
    /// <response code="200">Mappings returned.</response>
    /// <returns>A list of external provider mappings for the user.</returns>
    [HttpGet("Mappings/{userId}")]
    [Authorize(Policy = Policies.RequiresElevation)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult<IEnumerable<ExternalProviderMappingDto>>> GetUserMappings(
        [FromRoute, Required] Guid userId)
    {
        var mappings = await _externalAuthService.GetUserMappingsAsync(userId).ConfigureAwait(false);

        var dtos = mappings.Select(m => new ExternalProviderMappingDto
        {
            UserId = m.UserId,
            ProviderName = m.ProviderName,
            DateCreated = m.DateCreated,
            ForceExternalAuth = m.ForceExternalAuth
        });

        return Ok(dtos);
    }

    /// <summary>
    /// Initiates an external authentication flow.
    /// </summary>
    /// <param name="provider">The provider name.</param>
    /// <param name="request">The initiation request.</param>
    /// <response code="200">Authentication flow initiated.</response>
    /// <response code="404">Provider not found or not enabled.</response>
    /// <returns>The authorization URL to redirect to.</returns>
    [HttpPost("{provider}/Initiate")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<ExternalAuthInitiationDto>> InitiateAuthentication(
        [FromRoute, Required] string provider,
        [FromBody, Required] ExternalAuthInitiateRequest request)
    {
        var authProvider = FindProvider(provider);
        if (authProvider is null)
        {
            return NotFound("Provider not found or not enabled.");
        }

        var metadata = new Dictionary<string, string>();
        if (!string.IsNullOrEmpty(request.DeviceId))
        {
            metadata["DeviceId"] = request.DeviceId;
        }

        if (!string.IsNullOrEmpty(request.DeviceName))
        {
            metadata["DeviceName"] = request.DeviceName;
        }

        if (!string.IsNullOrEmpty(request.AppName))
        {
            metadata["AppName"] = request.AppName;
        }

        if (!string.IsNullOrEmpty(request.AppVersion))
        {
            metadata["AppVersion"] = request.AppVersion;
        }

        // Generate PKCE pair
        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = ComputeCodeChallenge(codeVerifier);
        metadata["CodeVerifier"] = codeVerifier;

        var state = _externalAuthService.GenerateState(metadata);

        var result = await authProvider.InitiateAuthentication(request.CallbackUrl, state, codeChallenge)
            .ConfigureAwait(false);

        return Ok(new ExternalAuthInitiationDto
        {
            AuthorizationUrl = result.AuthorizationUrl
        });
    }

    /// <summary>
    /// Handles the OAuth callback from an external provider.
    /// Returns an HTML page that posts the authentication result back to the opener window via postMessage.
    /// </summary>
    /// <param name="provider">The provider name.</param>
    /// <param name="code">The authorization code from the provider.</param>
    /// <param name="state">The CSRF state token.</param>
    /// <returns>An HTML page that communicates the result to the opener window.</returns>
    [HttpGet("{provider}/Callback")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ContentResult> HandleCallback(
        [FromRoute, Required] string provider,
        [FromQuery, Required] string code,
        [FromQuery, Required] string state)
    {
        try
        {
            var result = await ProcessCallback(provider, code, state).ConfigureAwait(false);
            var json = JsonSerializer.Serialize(result, JsonDefaults.Options);
            return Content(BuildCallbackHtml(json, null), "text/html");
        }
        catch (AuthenticationException ex)
        {
            _logger.LogWarning(ex, "SSO callback failed for provider {Provider}", provider);
            return Content(BuildCallbackHtml(null, ex.Message), "text/html");
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning(ex, "SSO callback error for provider {Provider}", provider);
            return Content(BuildCallbackHtml(null, ex.Message), "text/html");
        }
    }

    /// <summary>
    /// Handles the OAuth callback and returns JSON directly (for non-browser API clients).
    /// </summary>
    /// <param name="provider">The provider name.</param>
    /// <param name="code">The authorization code from the provider.</param>
    /// <param name="state">The CSRF state token.</param>
    /// <response code="200">User authenticated successfully.</response>
    /// <response code="400">Invalid state token or authentication failed.</response>
    /// <response code="403">External authentication is disabled or user creation not allowed.</response>
    /// <response code="404">Provider not found.</response>
    /// <returns>The authentication result containing the Jellyfin access token.</returns>
    [HttpPost("{provider}/Callback")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<AuthenticationResult>> HandleCallbackJson(
        [FromRoute, Required] string provider,
        [FromQuery, Required] string code,
        [FromQuery, Required] string state)
    {
        try
        {
            var result = await ProcessCallback(provider, code, state).ConfigureAwait(false);
            return Ok(result);
        }
        catch (AuthenticationException ex)
        {
            return BadRequest("Authentication failed: " + ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(ex.Message);
        }
    }

    /// <summary>
    /// Sets whether a user must use SSO login for a specific provider.
    /// </summary>
    /// <param name="provider">The provider name.</param>
    /// <param name="userId">The user ID.</param>
    /// <param name="force">Whether to force SSO login.</param>
    /// <response code="204">Setting updated.</response>
    /// <returns>No content.</returns>
    [HttpPatch("{provider}/Mapping/{userId}/ForceAuth")]
    [Authorize(Policy = Policies.RequiresElevation)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<ActionResult> SetForceExternalAuth(
        [FromRoute, Required] string provider,
        [FromRoute, Required] Guid userId,
        [FromQuery, Required] bool force)
    {
        await _externalAuthService.SetForceExternalAuthAsync(userId, provider, force).ConfigureAwait(false);
        return NoContent();
    }

    /// <summary>
    /// Unlinks an external provider account from a specific user (admin only).
    /// </summary>
    /// <param name="provider">The provider name.</param>
    /// <param name="userId">The user ID.</param>
    /// <response code="204">Account unlinked successfully.</response>
    /// <returns>No content on success.</returns>
    [HttpDelete("{provider}/UnlinkUser/{userId}")]
    [Authorize(Policy = Policies.RequiresElevation)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<ActionResult> UnlinkUserExternalAccount(
        [FromRoute, Required] string provider,
        [FromRoute, Required] Guid userId)
    {
        await _externalAuthService.RemoveProviderMapping(userId, provider).ConfigureAwait(false);
        return NoContent();
    }

    /// <summary>
    /// Links the current user's account to an external provider.
    /// </summary>
    /// <param name="provider">The provider name.</param>
    /// <param name="request">The initiation request containing callback URL.</param>
    /// <response code="200">Link flow initiated.</response>
    /// <response code="404">Provider not found.</response>
    /// <returns>The authorization URL to redirect to.</returns>
    [HttpPost("{provider}/Link")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<ExternalAuthInitiationDto>> LinkExternalAccount(
        [FromRoute, Required] string provider,
        [FromBody, Required] ExternalAuthInitiateRequest request)
    {
        var authProvider = FindProvider(provider);
        if (authProvider is null)
        {
            return NotFound("Provider not found or not enabled.");
        }

        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = ComputeCodeChallenge(codeVerifier);

        var metadata = new Dictionary<string, string> { ["CodeVerifier"] = codeVerifier };
        var state = _externalAuthService.GenerateState(metadata);

        var result = await authProvider.InitiateAuthentication(request.CallbackUrl, state, codeChallenge)
            .ConfigureAwait(false);

        return Ok(new ExternalAuthInitiationDto
        {
            AuthorizationUrl = result.AuthorizationUrl
        });
    }

    /// <summary>
    /// Unlinks the current user's account from an external provider.
    /// </summary>
    /// <param name="provider">The provider name.</param>
    /// <response code="204">Account unlinked successfully.</response>
    /// <response code="404">Provider not found.</response>
    /// <returns>No content on success.</returns>
    [HttpDelete("{provider}/Unlink")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult> UnlinkExternalAccount(
        [FromRoute, Required] string provider)
    {
        var userId = User.GetUserId();
        await _externalAuthService.RemoveProviderMapping(userId, provider).ConfigureAwait(false);
        return NoContent();
    }

    private async Task<AuthenticationResult> ProcessCallback(
        string provider,
        string code,
        string state)
    {
        if (!_config.Configuration.EnableExternalAuth)
        {
            throw new InvalidOperationException("External authentication is disabled.");
        }

        var authProvider = FindProvider(provider)
            ?? throw new InvalidOperationException("Provider not found or not enabled.");

        // Validate CSRF state token and retrieve device metadata
        if (!_externalAuthService.ValidateState(state, out var metadata))
        {
            _logger.LogWarning("Invalid or expired state token for provider {Provider}", provider);
            throw new AuthenticationException("Invalid or expired state token.");
        }

        string? deviceId = null;
        string? deviceName = null;
        string? appName = null;
        string? appVersion = null;
        string? codeVerifier = null;
        metadata?.TryGetValue("DeviceId", out deviceId);
        metadata?.TryGetValue("DeviceName", out deviceName);
        metadata?.TryGetValue("AppName", out appName);
        metadata?.TryGetValue("AppVersion", out appVersion);
        metadata?.TryGetValue("CodeVerifier", out codeVerifier);

        // Build callback URL from current request
        var callbackUrl = $"{Request.Scheme}://{Request.Host}{Request.PathBase}/Auth/SSO/{provider}/Callback";

        // Exchange authorization code for tokens (with PKCE verifier)
        var tokens = await authProvider.CompleteAuthentication(code, state, callbackUrl, codeVerifier)
            .ConfigureAwait(false);

        // Get user info from provider
        var userInfo = await authProvider.GetUserInfo(tokens.AccessToken)
            .ConfigureAwait(false);

        // Find existing mapping
        var user = await _externalAuthService.FindUserByProviderMapping(provider, userInfo.ProviderId)
            .ConfigureAwait(false);

        if (user is null)
        {
            // Try to find existing user by username for auto-linking
            if (_config.Configuration.AllowAutoLinkByEmail)
            {
                user = _userManager.GetUserByName(userInfo.Username);
            }

            if (user is not null)
            {
                // Auto-link existing user
                await _externalAuthService.CreateProviderMapping(user, provider, userInfo, tokens)
                    .ConfigureAwait(false);
            }
            else if (_config.Configuration.AllowExternalUserCreation)
            {
                // Create new user
                user = await _userManager.CreateUserAsync(userInfo.Username).ConfigureAwait(false);
                await _externalAuthService.CreateProviderMapping(user, provider, userInfo, tokens)
                    .ConfigureAwait(false);
                _logger.LogInformation(
                    "Created new user {Username} via external provider {Provider}",
                    userInfo.Username,
                    provider);
            }
            else
            {
                throw new AuthenticationException("No linked account found and user creation is disabled.");
            }
        }

        // Apply role mappings from provider claims
        ApplyRoleMappings(user, userInfo.Claims, authProvider.RoleMappings);

        // Issue Jellyfin session token via AuthenticateDirect (bypasses password check)
        return await _sessionManager.AuthenticateDirect(new AuthenticationRequest
        {
            App = appName ?? "SSO",
            AppVersion = appVersion ?? "0.0.0",
            DeviceId = deviceId ?? Guid.NewGuid().ToString("N"),
            DeviceName = deviceName ?? "SSO Login",
            RemoteEndPoint = HttpContext.GetNormalizedRemoteIP().ToString(),
            Username = user.Username,
            UserId = user.Id
        }).ConfigureAwait(false);
    }

    private static string BuildCallbackHtml(string? resultJson, string? error)
    {
        var messagePayload = error is not null
            ? $$"""{"error":"{{error.Replace("\"", "\\\"", StringComparison.Ordinal)}}"}"""
            : $$"""{"result":{{resultJson}}}""";

        return $$"""
            <!DOCTYPE html>
            <html>
            <head><title>SSO Authentication</title></head>
            <body>
            <p>Authentication complete. This window will close automatically.</p>
            <script>
            (function() {
                var msg = {{messagePayload}};
                if (window.opener) {
                    window.opener.postMessage({ type: 'SSOCallback', data: msg }, '*');
                    window.close();
                } else {
                    document.body.innerText = msg.error || 'Authenticated successfully. You may close this window.';
                }
            })();
            </script>
            </body>
            </html>
            """;
    }

    private IExternalAuthenticationProvider? FindProvider(string name)
    {
        return _externalProviders.FirstOrDefault(
            p => p.IsEnabled && string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));
    }

    private void ApplyRoleMappings(
        Jellyfin.Database.Implementations.Entities.User user,
        Dictionary<string, string> claims,
        IReadOnlyList<ExternalRoleMapping> roleMappings)
    {
        if (roleMappings.Count == 0 || claims.Count == 0)
        {
            return;
        }

        foreach (var mapping in roleMappings)
        {
            if (string.IsNullOrEmpty(mapping.ClaimName) || string.IsNullOrEmpty(mapping.Permission))
            {
                continue;
            }

            if (!Enum.TryParse<PermissionKind>(mapping.Permission, ignoreCase: true, out var permissionKind))
            {
                _logger.LogWarning("Unknown permission kind in role mapping: {Permission}", mapping.Permission);
                continue;
            }

            if (!claims.TryGetValue(mapping.ClaimName, out var claimValue))
            {
                continue;
            }

            // Check if the claim value matches — support both simple string and JSON array values
            bool matches = false;
            if (string.Equals(claimValue, mapping.ClaimValue, StringComparison.OrdinalIgnoreCase))
            {
                matches = true;
            }
            else if (claimValue.StartsWith('['))
            {
                // Try parsing as JSON array
                try
                {
                    var array = JsonSerializer.Deserialize<string[]>(claimValue);
                    if (array is not null)
                    {
                        matches = array.Any(v => string.Equals(v, mapping.ClaimValue, StringComparison.OrdinalIgnoreCase));
                    }
                }
                catch (JsonException)
                {
                    // Not valid JSON array, skip
                }
            }

            if (matches)
            {
                _logger.LogInformation(
                    "Role mapping applied: claim {Claim}={Value} -> {Permission}={Grant} for user {Username}",
                    mapping.ClaimName,
                    mapping.ClaimValue,
                    mapping.Permission,
                    mapping.Grant,
                    user.Username);
                user.SetPermission(permissionKind, mapping.Grant);
            }
        }
    }

    private static string GenerateCodeVerifier()
    {
        return Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
    }

    private static string ComputeCodeChallenge(string codeVerifier)
    {
        return Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));
    }

    private static string Base64UrlEncode(byte[] data)
    {
        return Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
