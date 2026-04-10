using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Jellyfin.Database.Implementations.Interfaces;

namespace Jellyfin.Database.Implementations.Entities;

/// <summary>
/// An entity representing a mapping between a Jellyfin user and an external authentication provider account.
/// </summary>
public class ExternalProviderMapping : IHasConcurrencyToken
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ExternalProviderMapping"/> class.
    /// </summary>
    /// <param name="providerName">The name of the external provider.</param>
    /// <param name="providerUserId">The user's unique ID from the external provider.</param>
    /// <param name="userId">The Jellyfin user ID.</param>
    public ExternalProviderMapping(string providerName, string providerUserId, Guid userId)
    {
        ProviderName = providerName;
        ProviderUserId = providerUserId;
        UserId = userId;
        DateCreated = DateTime.UtcNow;
        DateModified = DateTime.UtcNow;
    }

    /// <summary>
    /// Gets the primary key.
    /// </summary>
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; private set; }

    /// <summary>
    /// Gets or sets the associated Jellyfin user ID.
    /// </summary>
    public Guid UserId { get; set; }

    /// <summary>
    /// Gets the name of the external provider (e.g., "Google", "Microsoft").
    /// </summary>
    [MaxLength(255)]
    [StringLength(255)]
    public string ProviderName { get; private set; }

    /// <summary>
    /// Gets the user's unique ID from the external provider.
    /// </summary>
    [MaxLength(512)]
    [StringLength(512)]
    public string ProviderUserId { get; private set; }

    /// <summary>
    /// Gets or sets the encrypted access token from the provider.
    /// </summary>
    [MaxLength(2048)]
    [StringLength(2048)]
    public string? AccessToken { get; set; }

    /// <summary>
    /// Gets or sets the encrypted refresh token from the provider.
    /// </summary>
    [MaxLength(2048)]
    [StringLength(2048)]
    public string? RefreshToken { get; set; }

    /// <summary>
    /// Gets or sets the token expiry date.
    /// </summary>
    public DateTime? TokenExpiryDate { get; set; }

    /// <summary>
    /// Gets the date this mapping was created.
    /// </summary>
    public DateTime DateCreated { get; private set; }

    /// <summary>
    /// Gets or sets the date this mapping was last modified.
    /// </summary>
    public DateTime DateModified { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the user must authenticate via this external provider.
    /// </summary>
    public bool ForceExternalAuth { get; set; }

    /// <summary>
    /// Gets or sets the date of the last token refresh attempt.
    /// </summary>
    public DateTime? LastRefreshAttempt { get; set; }

    /// <summary>
    /// Gets or sets the associated user.
    /// </summary>
    [ForeignKey(nameof(UserId))]
    public virtual User? User { get; set; }

    /// <inheritdoc />
    [ConcurrencyCheck]
    public uint RowVersion { get; private set; }

    /// <inheritdoc/>
    public void OnSavingChanges()
    {
        RowVersion++;
    }
}
