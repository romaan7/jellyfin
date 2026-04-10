using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using MediaBrowser.Controller.Authentication;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO.Providers;

/// <summary>
/// Google OAuth2 external authentication provider.
/// </summary>
public class GoogleOAuthProvider : IExternalAuthenticationProvider
{
    private const string AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
    private const string TokenEndpoint = "https://oauth2.googleapis.com/token";
    private const string UserInfoEndpoint = "https://www.googleapis.com/oauth2/v2/userinfo";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<GoogleOAuthProvider> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="GoogleOAuthProvider"/> class.
    /// </summary>
    /// <param name="httpClientFactory">The HTTP client factory.</param>
    /// <param name="logger">The logger.</param>
    public GoogleOAuthProvider(
        IHttpClientFactory httpClientFactory,
        ILogger<GoogleOAuthProvider> logger)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    /// <inheritdoc/>
    public string Name => "Google";

    /// <inheritdoc/>
    public bool IsEnabled
    {
        get
        {
            var config = Plugin.Instance?.Configuration.GoogleOAuth;
            return config is not null
                && config.Enabled
                && !string.IsNullOrWhiteSpace(config.ClientId)
                && !string.IsNullOrWhiteSpace(config.ClientSecret);
        }
    }

    /// <inheritdoc/>
    public string? IconType => "google";

    /// <inheritdoc/>
    public IReadOnlyList<ExternalRoleMapping> RoleMappings =>
        Plugin.Instance?.Configuration.GoogleOAuth.RoleMappings
            .Select(m => new ExternalRoleMapping
            {
                ClaimName = m.ClaimName,
                ClaimValue = m.ClaimValue,
                Permission = m.Permission,
                Grant = m.Grant
            }).ToList() ?? [];

    /// <inheritdoc/>
    public Task<ExternalAuthInitiationResult> InitiateAuthentication(string callbackUrl, string state, string? codeChallenge = null)
    {
        var config = Plugin.Instance?.Configuration.GoogleOAuth
            ?? throw new InvalidOperationException("SSO plugin is not configured.");

        var queryParams = new Dictionary<string, string?>
        {
            ["client_id"] = config.ClientId,
            ["redirect_uri"] = callbackUrl,
            ["response_type"] = "code",
            ["scope"] = "openid profile email",
            ["state"] = state,
            ["access_type"] = "offline",
            ["prompt"] = "consent"
        };

        if (!string.IsNullOrEmpty(codeChallenge))
        {
            queryParams["code_challenge"] = codeChallenge;
            queryParams["code_challenge_method"] = "S256";
        }

        var authUrl = AuthorizationEndpoint + "?" + string.Join(
            "&",
            queryParams.Select(kvp => $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value ?? string.Empty)}"));

        return Task.FromResult(new ExternalAuthInitiationResult
        {
            AuthorizationUrl = authUrl,
            State = state
        });
    }

    /// <inheritdoc/>
    public async Task<ExternalAuthTokenResult> CompleteAuthentication(string code, string state, string callbackUrl, string? codeVerifier = null)
    {
        var config = Plugin.Instance?.Configuration.GoogleOAuth
            ?? throw new InvalidOperationException("SSO plugin is not configured.");

        var httpClient = _httpClientFactory.CreateClient(nameof(GoogleOAuthProvider));

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

        var response = await httpClient.PostAsync(TokenEndpoint, tokenRequest).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            var errorBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            _logger.LogError("Google token exchange failed: {StatusCode} {Body}", response.StatusCode, errorBody);
            throw new AuthenticationException("Failed to exchange authorization code for tokens.");
        }

        var tokenResponse = await response.Content.ReadFromJsonAsync<GoogleTokenResponse>().ConfigureAwait(false)
            ?? throw new AuthenticationException("Empty token response from Google.");

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
        var httpClient = _httpClientFactory.CreateClient(nameof(GoogleOAuthProvider));
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        var response = await httpClient.GetAsync(UserInfoEndpoint).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            var errorBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            _logger.LogError("Google user info request failed: {StatusCode} {Body}", response.StatusCode, errorBody);
            throw new AuthenticationException("Failed to retrieve user info from Google.");
        }

        var googleUser = await response.Content.ReadFromJsonAsync<GoogleUserInfo>().ConfigureAwait(false)
            ?? throw new AuthenticationException("Empty user info response from Google.");

        // Validate email domain if configured
        var config = Plugin.Instance?.Configuration.GoogleOAuth;
        if (config is not null
            && !string.IsNullOrWhiteSpace(config.AllowedDomains)
            && !string.IsNullOrEmpty(googleUser.Email))
        {
            var allowedDomains = config.AllowedDomains
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            var emailDomain = googleUser.Email.Split('@').LastOrDefault();
            if (allowedDomains.Length > 0
                && !allowedDomains.Contains(emailDomain, StringComparer.OrdinalIgnoreCase))
            {
                throw new AuthenticationException(
                    $"Email domain '{emailDomain}' is not in the list of allowed domains.");
            }
        }

        // Use email prefix as username, falling back to ID
        var username = !string.IsNullOrEmpty(googleUser.Email)
            ? googleUser.Email.Split('@')[0]
            : googleUser.Id;

        return new ExternalUserInfo
        {
            ProviderId = googleUser.Id,
            Email = googleUser.Email,
            Username = username,
            DisplayName = googleUser.Name,
            Claims = new Dictionary<string, string>
            {
                ["email"] = googleUser.Email ?? string.Empty,
                ["name"] = googleUser.Name ?? string.Empty,
                ["picture"] = googleUser.Picture ?? string.Empty,
                ["email_verified"] = googleUser.VerifiedEmail.ToString()
            }
        };
    }

    /// <inheritdoc/>
    public async Task<ExternalAuthTokenResult?> RefreshAccessToken(string refreshToken)
    {
        var config = Plugin.Instance?.Configuration.GoogleOAuth
            ?? throw new InvalidOperationException("SSO plugin is not configured.");

        var httpClient = _httpClientFactory.CreateClient(nameof(GoogleOAuthProvider));

        var formData = new Dictionary<string, string>
        {
            ["refresh_token"] = refreshToken,
            ["client_id"] = config.ClientId,
            ["client_secret"] = config.ClientSecret,
            ["grant_type"] = "refresh_token"
        };

        var response = await httpClient.PostAsync(TokenEndpoint, new FormUrlEncodedContent(formData)).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("Google token refresh failed: {StatusCode}", response.StatusCode);
            return null;
        }

        var tokenResponse = await response.Content.ReadFromJsonAsync<GoogleTokenResponse>().ConfigureAwait(false);
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

    private sealed class GoogleTokenResponse
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

    private sealed class GoogleUserInfo
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        [JsonPropertyName("email")]
        public string? Email { get; set; }

        [JsonPropertyName("verified_email")]
        public bool VerifiedEmail { get; set; }

        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("picture")]
        public string? Picture { get; set; }
    }
}
