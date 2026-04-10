using System;
using System.Collections.Concurrent;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO.Discovery;

/// <summary>
/// Fetches and caches OIDC discovery documents from issuer URLs.
/// </summary>
public class OidcDiscoveryService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<OidcDiscoveryService> _logger;
    private readonly ConcurrentDictionary<string, CachedDocument> _cache = new(StringComparer.OrdinalIgnoreCase);

    private static readonly TimeSpan CacheTtl = TimeSpan.FromHours(1);

    /// <summary>
    /// Initializes a new instance of the <see cref="OidcDiscoveryService"/> class.
    /// </summary>
    /// <param name="httpClientFactory">The HTTP client factory.</param>
    /// <param name="logger">The logger.</param>
    public OidcDiscoveryService(
        IHttpClientFactory httpClientFactory,
        ILogger<OidcDiscoveryService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    /// <summary>
    /// Gets the discovery document for the given issuer URL.
    /// Results are cached for one hour.
    /// </summary>
    /// <param name="issuerUrl">The OIDC issuer URL (e.g. https://accounts.google.com).</param>
    /// <returns>The discovered endpoints.</returns>
    public async Task<OidcDiscoveryDocument> GetDiscoveryDocumentAsync(string issuerUrl)
    {
        if (_cache.TryGetValue(issuerUrl, out var cached) && DateTime.UtcNow - cached.FetchedAt < CacheTtl)
        {
            return cached.Document;
        }

        var discoveryUrl = issuerUrl.TrimEnd('/') + "/.well-known/openid-configuration";
        _logger.LogInformation("Fetching OIDC discovery document from {Url}", discoveryUrl);

        var httpClient = _httpClientFactory.CreateClient(nameof(OidcDiscoveryService));
        var doc = await httpClient.GetFromJsonAsync<OidcDiscoveryDocument>(discoveryUrl).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Empty discovery document from {discoveryUrl}");

        if (string.IsNullOrEmpty(doc.AuthorizationEndpoint) || string.IsNullOrEmpty(doc.TokenEndpoint))
        {
            throw new InvalidOperationException($"Discovery document from {discoveryUrl} is missing required endpoints.");
        }

        _cache[issuerUrl] = new CachedDocument(doc, DateTime.UtcNow);
        _logger.LogInformation(
            "Cached OIDC discovery for {Issuer}: auth={AuthEndpoint}, token={TokenEndpoint}",
            issuerUrl,
            doc.AuthorizationEndpoint,
            doc.TokenEndpoint);

        return doc;
    }

    private sealed record CachedDocument(OidcDiscoveryDocument Document, DateTime FetchedAt);
}
