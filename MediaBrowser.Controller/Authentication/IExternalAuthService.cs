using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;

namespace MediaBrowser.Controller.Authentication;

/// <summary>
/// Service for managing external authentication provider mappings and state.
/// </summary>
public interface IExternalAuthService
{
    /// <summary>
    /// Finds a user by their external provider mapping.
    /// </summary>
    /// <param name="providerName">The name of the external provider.</param>
    /// <param name="providerUserId">The user's ID from the external provider.</param>
    /// <returns>The mapped user, or null if no mapping exists.</returns>
    Task<User?> FindUserByProviderMapping(string providerName, string providerUserId);

    /// <summary>
    /// Creates a mapping between a Jellyfin user and an external provider account.
    /// </summary>
    /// <param name="user">The Jellyfin user.</param>
    /// <param name="providerName">The name of the external provider.</param>
    /// <param name="userInfo">The external user info from the provider.</param>
    /// <param name="tokens">The authentication tokens from the provider.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task CreateProviderMapping(User user, string providerName, ExternalUserInfo userInfo, ExternalAuthTokenResult tokens);

    /// <summary>
    /// Removes a mapping between a Jellyfin user and an external provider account.
    /// </summary>
    /// <param name="userId">The Jellyfin user ID.</param>
    /// <param name="providerName">The name of the external provider.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task RemoveProviderMapping(Guid userId, string providerName);

    /// <summary>
    /// Gets all external provider mappings.
    /// </summary>
    /// <returns>A read-only list of all external provider mappings.</returns>
    Task<IReadOnlyList<ExternalProviderMapping>> GetAllMappingsAsync();

    /// <summary>
    /// Gets all external provider mappings for a specific user.
    /// </summary>
    /// <param name="userId">The Jellyfin user ID.</param>
    /// <returns>A read-only list of mappings for the user.</returns>
    Task<IReadOnlyList<ExternalProviderMapping>> GetUserMappingsAsync(Guid userId);

    /// <summary>
    /// Checks whether a user is forced to use external authentication.
    /// </summary>
    /// <param name="userId">The Jellyfin user ID.</param>
    /// <returns>True if the user must use SSO login.</returns>
    Task<bool> IsUserForcedExternalAuthAsync(Guid userId);

    /// <summary>
    /// Sets whether a user must use SSO login for a specific provider.
    /// </summary>
    /// <param name="userId">The Jellyfin user ID.</param>
    /// <param name="providerName">The provider name.</param>
    /// <param name="force">Whether to force SSO login.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task SetForceExternalAuthAsync(Guid userId, string providerName, bool force);

    /// <summary>
    /// Updates stored tokens for a provider mapping.
    /// </summary>
    /// <param name="mappingId">The mapping ID.</param>
    /// <param name="newTokens">The new tokens.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task UpdateTokensAsync(int mappingId, ExternalAuthTokenResult newTokens);

    /// <summary>
    /// Gets all mappings with expiring tokens that need refresh.
    /// </summary>
    /// <param name="expiryThreshold">Tokens expiring within this timespan will be included.</param>
    /// <returns>A list of mappings needing token refresh.</returns>
    Task<IReadOnlyList<ExternalProviderMapping>> GetMappingsNeedingRefreshAsync(TimeSpan expiryThreshold);

    /// <summary>
    /// Generates a cryptographically secure state token for CSRF protection,
    /// storing associated client device metadata.
    /// </summary>
    /// <param name="metadata">Optional metadata to associate with the state token.</param>
    /// <returns>The generated state token.</returns>
    string GenerateState(IReadOnlyDictionary<string, string>? metadata = null);

    /// <summary>
    /// Validates and consumes a state token, returning associated metadata.
    /// </summary>
    /// <param name="state">The state token to validate.</param>
    /// <param name="metadata">The metadata associated with the state token, if valid.</param>
    /// <returns>True if the state token is valid, false otherwise.</returns>
    bool ValidateState(string state, out IReadOnlyDictionary<string, string>? metadata);
}
