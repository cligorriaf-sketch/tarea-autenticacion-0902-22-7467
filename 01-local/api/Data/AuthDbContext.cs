using LocalAuth.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace LocalAuth.Api.Data;

public sealed class AuthDbContext(DbContextOptions<AuthDbContext> options) : DbContext(options)
{
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<TotpReplayState> TotpReplayStates => Set<TotpReplayState>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<RefreshToken>(entity =>
        {
            entity.HasKey(token => token.Id);
            entity.HasIndex(token => token.TokenHash).IsUnique();
            entity.Property(token => token.UserId).IsRequired();
            entity.Property(token => token.TokenHash).IsRequired();
        });
        modelBuilder.Entity<TotpReplayState>(entity =>
        {
            entity.HasKey(state => state.UserId);
            entity.Property(state => state.UserId).IsRequired();
        });
    }
}
