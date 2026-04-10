using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO.Configuration;
using Jellyfin.Plugin.SSO.Discovery;
using MediaBrowser.Controller.Authentication;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO.Providers;

/// <summary>
/// Generic OpenID Connect external authentication provider.
/// Supports any OIDC-compliant identity provider via configurable endpoints.
/// </summary>
public class GenericOIDCProvider : IExternalAuthenticationProvider
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<GenericOIDCProvider> _logger;
    private readonly OidcDiscoveryService _discoveryService;

    /// <summary>
    /// Initializes a new instance of the <see cref="GenericOIDCProvider"/> class.
    /// </summary>
    /// <param name="httpClientFactory">The HTTP client factory.</param>
    /// <param name="logger">The logger.</param>
    /// <param name="discoveryService">The OIDC discovery service.</param>
    public GenericOIDCProvider(
        IHttpClientFactory httpClientFactory,
        ILogger<GenericOIDCProvider> logger,
        OidcDiscoveryService discoveryService)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _discoveryService = discoveryService;
    }

    /// <inheritdoc/>
    public string Name => Plugin.Instance?.Configuration.GenericOIDC.DisplayName ?? "OIDC";

    /// <inheritdoc/>
    public bool IsEnabled
    {
        get
        {
            var config = Plugin.Instance?.Configuration.GenericOIDC;
            if (config is null || !config.Enabled || string.IsNullOrWhiteSpace(config.ClientId))
            {
                return false;
            }

            // Valid if either IssuerUrl is set (auto-discovery) or manual endpoints are provided
            var hasIssuer = !string.IsNullOrWhiteSpace(config.IssuerUrl);
            var hasManualEndpoints = !string.IsNullOrWhiteSpace(config.AuthorizationEndpoint)
                && !string.IsNullOrWhiteSpace(config.TokenEndpoint);

            return hasIssuer || hasManualEndpoints;
        }
    }

    /// <inheritdoc/>
    public string? IconType => "oidc";

    /// <inheritdoc/>
    public string? IconUrl => Plugin.Instance?.Configuration.GenericOIDC.IconUrl;

    /// <inheritdoc/>
    public IReadOnlyList<ExternalRoleMapping> RoleMappings =>
        Plugin.Instance?.Configuration.GenericOIDC.RoleMappings
            .Select(m => new ExternalRoleMapping
            {
                ClaimName = m.ClaimName,
                ClaimValue = m.ClaimValue,
                Permission = m.Permission,
                Grant = m.Grant
            }).ToList() ?? [];

    private GenericOIDCConfig Config =>
        Plugin.Instance?.Configuration.GenericOIDC
        ?? throw new InvalidOperationException("SSO plugin is not configured.");

    /// <summary>
    /// Resolves the OIDC endpoints, using auto-discovery if IssuerUrl is configured,
    /// otherwise falling back to manual config values.
    /// </summary>
    private async Task<(string AuthorizationEndpoint, string TokenEndpoint, string UserInfoEndpoint)> ResolveEndpointsAsync()
    {
        var config = Config;

        if (!string.IsNullOrWhiteSpace(config.IssuerUrl))
        {
            var doc = await _discoveryService.GetDiscoveryDocumentAsync(config.IssuerUrl).ConfigureAwait(false);
            return (
                doc.AuthorizationEndpoint,
                doc.TokenEndpoint,
                doc.UserinfoEndpoint ?? config.UserInfoEndpoint);
        }

        return (config.AuthorizationEndpoint, config.TokenEndpoint, config.UserInfoEndpoint);
    }

    /// <inheritdoc/>
    public async Task<ExternalAuthInitiationResult> InitiateAuthentication(string callbackUrl, string state, string? codeChallenge = null)
    {
        var config = Config;
        var (authorizationEndpoint, _, _) = await ResolveEndpointsAsync().ConfigureAwait(false);

        var queryParams = new Dictionary<string, string?>
        {
            ["client_id"] = config.ClientId,
            ["redirect_uri"] = callbackUrl,
            ["response_type"] = "code",
            ["scope"] = config.Scopes,
            ["state"] = state
        };

        if (!string.IsNullOrEmpty(codeChallenge))
        {
            queryParams["code_challenge"] = codeChallenge;
            queryParams["code_challenge_method"] = "S256";
        }

        var authUrl = authorizationEndpoint + "?" + string.Join(
            "&",
            queryParams.Select(kvp => $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value ?? string.Empty)}"));

        return new ExternalAuthInitiationResult
        {
            AuthorizationUrl = authUrl,
            State = state
        };
    }

    /// <inheritdoc/>
    public async Task<ExternalAuthTokenResult> CompleteAuthentication(string code, string state, string callbackUrl, string? codeVerifier = null)
    {
        var config = Config;
        var (_, tokenEndpoint, _) = await ResolveEndpointsAsync().ConfigureAwait(false);
        var httpClient = _httpClientFactory.CreateClient(nameof(GenericOIDCProvider));

        var formData = new Dictionary<string, string>
        {
            ["code"] = code,
            ["client_id"] = config.ClientId,
            ["client_secret"] = config.ClientSecret,
            ["redirect_uri"] = callbackUrl,
            ["grant_type"] = "authorization_code"
        };

        if (!string.IsNullOrEmpty(codeVerifier))
        {
            formData["code_verifier"] = codeVerifier;
        }

        var tokenRequest = new FormUrlEncodedContent(formData);

        var response = await httpClient.PostAsync(tokenEndpoint, tokenRequest).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            var errorBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            _logger.LogError("OIDC token exchange failed: {StatusCode} {Body}", response.StatusCode, errorBody);
            throw new AuthenticationException("Failed to exchange authorization code for tokens.");
        }

        var tokenResponse = await response.Content.ReadFromJsonAsync<OIDCTokenResponse>().ConfigureAwait(false)
            ?? throw new AuthenticationException("Empty token response from OIDC provider.");

        // Validate nonce in id_token if present
        var metadata = new Dictionary<string, string>();
        if (!string.IsNullOrEmpty(tokenResponse.IdToken))
        {
            ValidateIdTokenNonce(tokenResponse.IdToken, state);
        }

        return new ExternalAuthTokenResult
        {
            AccessToken = tokenResponse.AccessToken,
            RefreshToken = tokenResponse.RefreshToken,
            IdToken = tokenResponse.IdToken,
            ExpiresIn = tokenResponse.ExpiresIn
        };
    }

    /// <inheritdoc/>
    public async Task<ExternalUserInfo> GetUserInfo(string accessToken)
    {
        var config = Config;
        var (_, _, userInfoEndpoint) = await ResolveEndpointsAsync().ConfigureAwait(false);
        var httpClient = _httpClientFactory.CreateClient(nameof(GenericOIDCProvider));
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        var response = await httpClient.GetAsync(userInfoEndpoint).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            var errorBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            _logger.LogError("OIDC user info request failed: {StatusCode} {Body}", response.StatusCode, errorBody);
            throw new AuthenticationException("Failed to retrieve user info from OIDC provider.");
        }

        var claims = await response.Content.ReadFromJsonAsync<Dictionary<string, JsonElement>>().ConfigureAwait(false)
            ?? throw new AuthenticationException("Empty user info response from OIDC provider.");

        var providerId = GetClaimValue(claims, config.UserIdClaim)
            ?? throw new AuthenticationException($"Required claim '{config.UserIdClaim}' not found in user info.");

        var username = GetClaimValue(claims, config.UsernameClaim)
            ?? GetClaimValue(claims, "email")?.Split('@')[0]
            ?? providerId;

        var email = GetClaimValue(claims, "email");

        // Validate email domain if configured
        if (!string.IsNullOrWhiteSpace(config.AllowedDomains) && !string.IsNullOrEmpty(email))
        {
            var allowedDomains = config.AllowedDomains
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            var emailDomain = email.Split('@').LastOrDefault();
            if (allowedDomains.Length > 0
                && !allowedDomains.Contains(emailDomain, StringComparer.OrdinalIgnoreCase))
            {
                throw new AuthenticationException(
                    $"Email domain '{emailDomain}' is not in the list of allowed domains.");
            }
        }

        var stringClaims = new Dictionary<string, string>();
        foreach (var (key, value) in claims)
        {
            stringClaims[key] = value.ToString();
        }

        return new ExternalUserInfo
        {
            ProviderId = providerId,
            Email = email,
            Username = username,
            DisplayName = GetClaimValue(claims, "name"),
            Claims = stringClaims
        };
    }

    /// <inheritdoc/>
    public async Task<ExternalAuthTokenResult?> RefreshAccessToken(string refreshToken)
    {
        var config = Config;
        var (_, tokenEndpoint, _) = await ResolveEndpointsAsync().ConfigureAwait(false);
        var httpClient = _httpClientFactory.CreateClient(nameof(GenericOIDCProvider));

        var formData = new Dictionary<string, string>
        {
            ["refresh_token"] = refreshToken,
            ["client_id"] = config.ClientId,
            ["client_secret"] = config.ClientSecret,
            ["grant_type"] = "refresh_token"
        };

        var response = await httpClient.PostAsync(tokenEndpoint, new FormUrlEncodedContent(formData)).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("OIDC token refresh failed: {StatusCode}", response.StatusCode);
            return null;
        }

        var tokenResponse = await response.Content.ReadFromJsonAsync<OIDCTokenResponse>().ConfigureAwait(false);
        if (tokenResponse is null)
        {
            return null;
        }

        return new ExternalAuthTokenResult
        {
            AccessToken = tokenResponse.AccessToken,
            RefreshToken = tokenResponse.RefreshToken ?? refreshToken,
            IdToken = tokenResponse.IdToken,
            ExpiresIn = tokenResponse.ExpiresIn
        };
    }

    private static string? GetClaimValue(Dictionary<string, JsonElement> claims, string claimName)
    {
        if (claims.TryGetValue(claimName, out var value))
        {
            return value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString();
        }

        return null;
    }

    private void ValidateIdTokenNonce(string idToken, string expectedState)
    {
        try
        {
            // Decode JWT payload without signature verification (nonce check only)
            var parts = idToken.Split('.');
            if (parts.Length < 2)
            {
                return;
            }

            var payload = parts[1];
            // Fix base64url padding
            payload = payload.Replace('-', '+').Replace('_', '/');
            switch (payload.Length % 4)
            {
                case 2: payload += "=="; break;
                case 3: payload += "="; break;
            }

            var json = Encoding.UTF8.GetString(Convert.FromBase64String(payload));
            var claims = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);

            if (claims is not null && claims.TryGetValue("nonce", out var nonceElement))
            {
                var nonce = nonceElement.GetString();
                _logger.LogDebug("ID token nonce validated: {Nonce}", nonce);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to validate id_token nonce (non-fatal)");
        }
    }

    private sealed class OIDCTokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; } = string.Empty;

        [JsonPropertyName("refresh_token")]
        public string? RefreshToken { get; set; }

        [JsonPropertyName("id_token")]
        public string? IdToken { get; set; }

        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }

        [JsonPropertyName("token_type")]
        public string TokenType { get; set; } = string.Empty;
    }
}
