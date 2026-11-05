using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using LocalAuth.Api.Data;
using LocalAuth.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace LocalAuth.Api.Services;

public sealed class TokenService(
    AuthDbContext database,
    IConfiguration configuration,
    TimeProvider timeProvider)
{
    public static string HashRefreshToken(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    public async Task<TokenPair> IssuePairAsync(string userId, CancellationToken cancellationToken)
    {
        var refreshToken = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var now = timeProvider.GetUtcNow().UtcDateTime;
        database.RefreshTokens.Add(new RefreshToken
        {
            UserId = userId,
            TokenHash = HashRefreshToken(refreshToken),
            CreatedAt = now,
            ExpiresAt = now.AddDays(7)
        });
        await database.SaveChangesAsync(cancellationToken);

        var signingKey = configuration["Jwt:SigningKey"]
            ?? throw new InvalidOperationException("Configure Jwt:SigningKey using User Secrets.");
        var issuer = configuration["Jwt:Issuer"]!;
        var audience = configuration["Jwt:Audience"]!;
        var minutes = configuration.GetValue("Jwt:AccessTokenMinutes", 15);
        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)),
            SecurityAlgorithms.HmacSha256);
        var jwt = new JwtSecurityToken(
            issuer,
            audience,
            [new Claim(JwtRegisteredClaimNames.Sub, userId)],
            now,
            now.AddMinutes(minutes),
            credentials);

        return new TokenPair(new JwtSecurityTokenHandler().WriteToken(jwt), refreshToken);
    }
}

public sealed record TokenPair(string AccessToken, string RefreshToken);
