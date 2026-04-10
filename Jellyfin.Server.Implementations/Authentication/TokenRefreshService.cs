using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MediaBrowser.Controller.Authentication;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Server.Implementations.Authentication;

/// <summary>
/// Background service that periodically refreshes expiring external provider tokens.
/// </summary>
public class TokenRefreshService : IHostedService, IDisposable
{
    private readonly IExternalAuthService _externalAuthService;
    private readonly IEnumerable<IExternalAuthenticationProvider> _providers;
    private readonly ILogger<TokenRefreshService> _logger;
    private Timer? _timer;
    private bool _disposed;

    private static readonly TimeSpan RefreshInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan ExpiryThreshold = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenRefreshService"/> class.
    /// </summary>
    /// <param name="externalAuthService">The external auth service.</param>
    /// <param name="providers">The registered external auth providers.</param>
    /// <param name="logger">The logger.</param>
    public TokenRefreshService(
        IExternalAuthService externalAuthService,
        IEnumerable<IExternalAuthenticationProvider> providers,
        ILogger<TokenRefreshService> logger)
    {
        _externalAuthService = externalAuthService;
        _providers = providers;
        _logger = logger;
    }

    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Token refresh service started");
        _timer = new Timer(DoRefresh, null, RefreshInterval, RefreshInterval);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Token refresh service stopping");
        _timer?.Change(Timeout.Infinite, 0);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases unmanaged and optionally managed resources.
    /// </summary>
    /// <param name="disposing">Whether to release managed resources.</param>
    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            _timer?.Dispose();
        }

        _disposed = true;
    }

    private async void DoRefresh(object? state)
    {
        try
        {
            var mappings = await _externalAuthService.GetMappingsNeedingRefreshAsync(ExpiryThreshold)
                .ConfigureAwait(false);

            if (mappings.Count == 0)
            {
                return;
            }

            _logger.LogDebug("Found {Count} token(s) needing refresh", mappings.Count);

            foreach (var mapping in mappings)
            {
                try
                {
                    var provider = _providers.FirstOrDefault(
                        p => string.Equals(p.Name, mapping.ProviderName, StringComparison.OrdinalIgnoreCase));

                    if (provider is null || string.IsNullOrEmpty(mapping.RefreshToken))
                    {
                        continue;
                    }

                    var newTokens = await provider.RefreshAccessToken(mapping.RefreshToken)
                        .ConfigureAwait(false);

                    if (newTokens is not null)
                    {
                        await _externalAuthService.UpdateTokensAsync(mapping.Id, newTokens)
                            .ConfigureAwait(false);

                        _logger.LogInformation(
                            "Refreshed token for user {UserId} provider {Provider}",
                            mapping.UserId,
                            mapping.ProviderName);
                    }
                    else
                    {
                        _logger.LogWarning(
                            "Token refresh returned null for user {UserId} provider {Provider}",
                            mapping.UserId,
                            mapping.ProviderName);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(
                        ex,
                        "Failed to refresh token for user {UserId} provider {Provider}",
                        mapping.UserId,
                        mapping.ProviderName);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in token refresh cycle");
        }
    }
}
