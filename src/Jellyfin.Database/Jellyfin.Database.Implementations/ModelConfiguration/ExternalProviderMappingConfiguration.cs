using Jellyfin.Database.Implementations.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Jellyfin.Database.Implementations.ModelConfiguration;

/// <summary>
/// FluentAPI configuration for the ExternalProviderMapping entity.
/// </summary>
public class ExternalProviderMappingConfiguration : IEntityTypeConfiguration<ExternalProviderMapping>
{
    /// <inheritdoc/>
    public void Configure(EntityTypeBuilder<ExternalProviderMapping> builder)
    {
        builder
            .HasOne(m => m.User)
            .WithMany(u => u.ExternalProviderMappings)
            .HasForeignKey(m => m.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        builder
            .HasIndex(m => new { m.ProviderName, m.ProviderUserId })
            .IsUnique();

        builder
            .HasIndex(m => m.UserId);
    }
}
