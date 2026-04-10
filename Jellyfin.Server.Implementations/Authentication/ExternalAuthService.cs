using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations;
using Jellyfin.Database.Implementations.Entities;
using MediaBrowser.Controller.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Server.Implementations.Authentication;

/// <summary>
/// Service for managing external authentication provider mappings and CSRF state tokens.
/// </summary>
public class ExternalAuthService : IExternalAuthService
{
    private readonly IDbContextFactory<JellyfinDbContext> _dbProvider;
    private readonly ILogger<ExternalAuthService> _logger;
    private readonly ConcurrentDictionary<string, StateTokenEntry> _stateTokens = new();

    private static readonly TimeSpan StateTokenLifetime = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Initializes a new instance of the <see cref="ExternalAuthService"/> class.
    /// </summary>
    /// <param name="dbProvider">The database context factory.</param>
    /// <param name="logger">The logger.</param>
    public ExternalAuthService(
        IDbContextFactory<JellyfinDbContext> dbProvider,
        ILogger<ExternalAuthService> logger)
    {
        _dbProvider = dbProvider;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<User?> FindUserByProviderMapping(string providerName, string providerUserId)
    {
        var dbContext = await _dbProvider.CreateDbContextAsync().ConfigureAwait(false);
        await using (dbContext.ConfigureAwait(false))
        {
            var mapping = await dbContext.ExternalProviderMappings
                .Include(m => m.User)
                .FirstOrDefaultAsync(m =>
                    m.ProviderName == providerName
                    && m.ProviderUserId == providerUserId)
                .ConfigureAwait(false);

            return mapping?.User;
        }
    }

    /// <inheritdoc />
    public async Task CreateProviderMapping(
        User user,
        string providerName,
        ExternalUserInfo userInfo,
        ExternalAuthTokenResult tokens)
    {
        var dbContext = await _dbProvider.CreateDbContextAsync().ConfigureAwait(false);
        await using (dbContext.ConfigureAwait(false))
        {
            var mapping = new ExternalProviderMapping(providerName, userInfo.ProviderId, user.Id)
            {
                AccessToken = tokens.AccessToken,
                RefreshToken = tokens.RefreshToken,
                TokenExpiryDate = tokens.ExpiresIn > 0
                    ? DateTime.UtcNow.AddSeconds(tokens.ExpiresIn)
                    : null
            };

            dbContext.ExternalProviderMappings.Add(mapping);
            await dbContext.SaveChangesAsync().ConfigureAwait(false);

            _logger.LogInformation(
                "Created external provider mapping for user {Username} with provider {ProviderName}",
                user.Username,
                providerName);
        }
    }

    /// <inheritdoc />
    public async Task RemoveProviderMapping(Guid userId, string providerName)
    {
        var dbContext = await _dbProvider.CreateDbContextAsync().ConfigureAwait(false);
        await using (dbContext.ConfigureAwait(false))
        {
            var mapping = await dbContext.ExternalProviderMappings
                .FirstOrDefaultAsync(m =>
                    m.UserId.Equals(userId)
                    && m.ProviderName == providerName)
                .ConfigureAwait(false);

            if (mapping is not null)
            {
                dbContext.ExternalProviderMappings.Remove(mapping);
                await dbContext.SaveChangesAsync().ConfigureAwait(false);

                _logger.LogInformation(
                    "Removed external provider mapping for user {UserId} with provider {ProviderName}",
                    userId,
                    providerName);
            }
        }
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<ExternalProviderMapping>> GetAllMappingsAsync()
    {
        var dbContext = await _dbProvider.CreateDbContextAsync().ConfigureAwait(false);
        await using (dbContext.ConfigureAwait(false))
        {
            return await dbContext.ExternalProviderMappings
                .AsNoTracking()
                .ToListAsync()
                .ConfigureAwait(false);
        }
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<ExternalProviderMapping>> GetUserMappingsAsync(Guid userId)
    {
        var dbContext = await _dbProvider.CreateDbContextAsync().ConfigureAwait(false);
        await using (dbContext.ConfigureAwait(false))
        {
            return await dbContext.ExternalProviderMappings
                .AsNoTracking()
                .Where(m => m.UserId.Equals(userId))
                .ToListAsync()
                .ConfigureAwait(false);
        }
    }

    /// <inheritdoc />
    public async Task<bool> IsUserForcedExternalAuthAsync(Guid userId)
    {
        var dbContext = await _dbProvider.CreateDbContextAsync().ConfigureAwait(false);
        await using (dbContext.ConfigureAwait(false))
        {
            return await dbContext.ExternalProviderMappings
                .AsNoTracking()
                .AnyAsync(m => m.UserId.Equals(userId) && m.ForceExternalAuth)
                .ConfigureAwait(false);
        }
    }

    /// <inheritdoc />
    public async Task SetForceExternalAuthAsync(Guid userId, string providerName, bool force)
    {
        var dbContext = await _dbProvider.CreateDbContextAsync().ConfigureAwait(false);
        await using (dbContext.ConfigureAwait(false))
        {
            var mapping = await dbContext.ExternalProviderMappings
                .FirstOrDefaultAsync(m =>
                    m.UserId.Equals(userId)
                    && m.ProviderName == providerName)
                .ConfigureAwait(false);

            if (mapping is not null)
            {
                mapping.ForceExternalAuth = force;
                mapping.DateModified = DateTime.UtcNow;
                await dbContext.SaveChangesAsync().ConfigureAwait(false);
            }
        }
    }

    /// <inheritdoc />
    public async Task UpdateTokensAsync(int mappingId, ExternalAuthTokenResult newTokens)
    {
        var dbContext = await _dbProvider.CreateDbContextAsync().ConfigureAwait(false);
        await using (dbContext.ConfigureAwait(false))
        {
            var mapping = await dbContext.ExternalProviderMappings
                .FirstOrDefaultAsync(m => m.Id == mappingId)
                .ConfigureAwait(false);

            if (mapping is not null)
            {
                mapping.AccessToken = newTokens.AccessToken;
                if (!string.IsNullOrEmpty(newTokens.RefreshToken))
                {
                    mapping.RefreshToken = newTokens.RefreshToken;
                }

                mapping.TokenExpiryDate = newTokens.ExpiresIn > 0
                    ? DateTime.UtcNow.AddSeconds(newTokens.ExpiresIn)
                    : null;
                mapping.LastRefreshAttempt = DateTime.UtcNow;
                mapping.DateModified = DateTime.UtcNow;
                await dbContext.SaveChangesAsync().ConfigureAwait(false);
            }
        }
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<ExternalProviderMapping>> GetMappingsNeedingRefreshAsync(TimeSpan expiryThreshold)
    {
        var dbContext = await _dbProvider.CreateDbContextAsync().ConfigureAwait(false);
        await using (dbContext.ConfigureAwait(false))
        {
            var threshold = DateTime.UtcNow.Add(expiryThreshold);
            var refreshCooldown = DateTime.UtcNow.AddMinutes(-5);

            return await dbContext.ExternalProviderMappings
                .AsNoTracking()
                .Where(m =>
                    m.RefreshToken != null
                    && m.TokenExpiryDate != null
                    && m.TokenExpiryDate < threshold
                    && (m.LastRefreshAttempt == null || m.LastRefreshAttempt < refreshCooldown))
                .ToListAsync()
                .ConfigureAwait(false);
        }
    }

    /// <inheritdoc />
    public string GenerateState(IReadOnlyDictionary<string, string>? metadata = null)
    {
        CleanupExpiredTokens();

        var state = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        _stateTokens[state] = new StateTokenEntry(DateTime.UtcNow, metadata);
        return state;
    }

    /// <inheritdoc />
    public bool ValidateState(string state, out IReadOnlyDictionary<string, string>? metadata)
    {
        metadata = null;
        if (!_stateTokens.TryRemove(state, out var entry))
        {
            return false;
        }

        if (DateTime.UtcNow - entry.CreatedAt >= StateTokenLifetime)
        {
            return false;
        }

        metadata = entry.Metadata;
        return true;
    }

    private void CleanupExpiredTokens()
    {
        var expiry = DateTime.UtcNow - StateTokenLifetime;
        foreach (var kvp in _stateTokens)
        {
            if (kvp.Value.CreatedAt < expiry)
            {
                _stateTokens.TryRemove(kvp.Key, out _);
            }
        }
    }

    private sealed record StateTokenEntry(DateTime CreatedAt, IReadOnlyDictionary<string, string>? Metadata);
}
