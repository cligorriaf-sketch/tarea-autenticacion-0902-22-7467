using System.Security.Cryptography;
using System.Text;
using LocalAuth.Api.Data;
using LocalAuth.Api.Models;
using LocalAuth.Api.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("AuthDatabase")));
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddScoped<TokenService>();
builder.Services.AddCors(options => options.AddDefaultPolicy(policy =>
    policy.WithOrigins("http://localhost:5173").AllowAnyHeader().AllowAnyMethod()));

var signingKey = builder.Configuration["Jwt:SigningKey"]
    ?? throw new InvalidOperationException("Set Jwt:SigningKey with dotnet user-secrets.");
if (Encoding.UTF8.GetByteCount(signingKey) < 32)
{
    throw new InvalidOperationException("Jwt:SigningKey must contain at least 32 UTF-8 bytes.");
}

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidateAudience = true,
        ValidAudience = builder.Configuration["Jwt:Audience"],
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)),
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromSeconds(30)
    };
});
builder.Services.AddAuthorization();
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("auth-fixed-window", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            }));
});

var app = builder.Build();
await using (var scope = app.Services.CreateAsyncScope())
{
    var database = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    await database.Database.EnsureCreatedAsync();
    await database.Database.ExecuteSqlRawAsync(
        """
        CREATE TABLE IF NOT EXISTS TotpReplayStates (
            UserId TEXT NOT NULL PRIMARY KEY,
            LastAcceptedStep INTEGER NOT NULL
        )
        """);
}

app.UseRouting();
app.UseCors();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/api/auth/login", async (
    LoginRequest request,
    IConfiguration configuration,
    TokenService tokens,
    AuthDbContext database,
    TimeProvider timeProvider,
    CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.Username)
        || string.IsNullOrEmpty(request.Password)
        || !ValidPassword(request.Username, request.Password, configuration))
    {
        return Results.Unauthorized();
    }

    var totpSecret = configuration["Demo:TotpSecret"];
    if (!string.IsNullOrWhiteSpace(totpSecret))
    {
        if (string.IsNullOrEmpty(request.Code))
        {
            return Results.Accepted(value: new { twoFactorRequired = true });
        }

        var userId = configuration["Demo:UserId"] ?? "demo-user";
        if (string.IsNullOrEmpty(request.Code)
            || !await VerifyAndConsumeTotpAsync(
                database,
                totpSecret,
                userId,
                request.Code,
                timeProvider.GetUtcNow().UtcDateTime,
                cancellationToken))
        {
            return Results.Unauthorized();
        }
    }

    var pair = await tokens.IssuePairAsync(
        configuration["Demo:UserId"] ?? "demo-user", cancellationToken);
    return Results.Ok(new { accessToken = pair.AccessToken, refreshToken = pair.RefreshToken });
}).RequireRateLimiting("auth-fixed-window");

app.MapPost("/api/auth/2fa/verify", async (
    TwoFactorRequest request,
    IConfiguration configuration,
    TokenService tokens,
    AuthDbContext database,
    TimeProvider timeProvider,
    CancellationToken cancellationToken) =>
{
    var secret = configuration["Demo:TotpSecret"];
    if (string.IsNullOrWhiteSpace(secret)
        || string.IsNullOrEmpty(request.Username)
        || string.IsNullOrEmpty(request.Password)
        || !ValidPassword(request.Username, request.Password, configuration))
    {
        return Results.Unauthorized();
    }

    var userId = configuration["Demo:UserId"] ?? "demo-user";
    if (!await VerifyAndConsumeTotpAsync(
        database,
        secret,
        userId,
        request.Code,
        timeProvider.GetUtcNow().UtcDateTime,
        cancellationToken))
    {
        return Results.Unauthorized();
    }

    var pair = await tokens.IssuePairAsync(
        userId, cancellationToken);
    return Results.Ok(new { accessToken = pair.AccessToken, refreshToken = pair.RefreshToken });
}).RequireRateLimiting("auth-fixed-window");

app.MapPost("/api/auth/refresh", async (
    RefreshRequest request,
    AuthDbContext database,
    TokenService tokens,
    TimeProvider timeProvider,
    CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.RefreshToken))
    {
        return Results.Unauthorized();
    }

    var now = timeProvider.GetUtcNow().UtcDateTime;
    var hash = TokenService.HashRefreshToken(request.RefreshToken);
    await using var transaction = await database.Database.BeginTransactionAsync(cancellationToken);
    var current = await database.RefreshTokens.SingleOrDefaultAsync(
        item => item.TokenHash == hash, cancellationToken);
    if (current is null)
    {
        return Results.Unauthorized();
    }

    if (current.RevokedAt is not null)
    {
        await RevokeActiveTokens(database, current.UserId, now, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return Results.Unauthorized();
    }

    if (current.ExpiresAt <= now)
    {
        return Results.Unauthorized();
    }

    var claimed = await database.RefreshTokens
        .Where(item => item.Id == current.Id && item.RevokedAt == null && item.ExpiresAt > now)
        .ExecuteUpdateAsync(
            update => update.SetProperty(item => item.RevokedAt, now),
            cancellationToken);
    if (claimed != 1)
    {
        var latest = await database.RefreshTokens.AsNoTracking()
            .SingleOrDefaultAsync(item => item.Id == current.Id, cancellationToken);
        if (latest?.RevokedAt is not null)
        {
            await RevokeActiveTokens(database, latest.UserId, now, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }

        return Results.Unauthorized();
    }

    current.RevokedAt = now;
    var pair = await tokens.IssuePairAsync(current.UserId, cancellationToken);
    var replacement = await database.RefreshTokens.SingleAsync(
        item => item.TokenHash == TokenService.HashRefreshToken(pair.RefreshToken),
        cancellationToken);
    current.ReplacedByTokenId = replacement.Id;
    await database.SaveChangesAsync(cancellationToken);
    await transaction.CommitAsync(cancellationToken);
    return Results.Ok(new { accessToken = pair.AccessToken, refreshToken = pair.RefreshToken });
});

app.MapPost("/api/auth/logout", async (
    RefreshRequest request,
    AuthDbContext database,
    TimeProvider timeProvider,
    CancellationToken cancellationToken) =>
{
    if (!string.IsNullOrWhiteSpace(request.RefreshToken))
    {
        var hash = TokenService.HashRefreshToken(request.RefreshToken);
        var token = await database.RefreshTokens.SingleOrDefaultAsync(
            item => item.TokenHash == hash, cancellationToken);
        if (token is not null && token.RevokedAt is null)
        {
            token.RevokedAt = timeProvider.GetUtcNow().UtcDateTime;
            await database.SaveChangesAsync(cancellationToken);
        }
    }

    return Results.Ok();
});

app.MapGet("/api/health", () => Results.Ok(new { status = "ok" }));
app.Run();

static bool ValidPassword(string username, string password, IConfiguration configuration)
{
    var expectedUsername = configuration["Demo:Username"];
    var encodedHash = configuration["Demo:PasswordHash"];
    if (string.IsNullOrEmpty(expectedUsername) || string.IsNullOrEmpty(encodedHash))
    {
        throw new InvalidOperationException(
            "Configure Demo:Username and Demo:PasswordHash using User Secrets.");
    }

    var parts = encodedHash.Split('$');
    if (parts.Length != 3
        || !int.TryParse(parts[0], out var iterations)
        || iterations < 310_000)
    {
        throw new InvalidOperationException("Demo:PasswordHash has an invalid PBKDF2 format.");
    }

    var usernameMatches = string.Equals(username, expectedUsername, StringComparison.Ordinal);
    byte[] salt;
    byte[] expectedHash;
    try
    {
        salt = Convert.FromBase64String(parts[1]);
        expectedHash = Convert.FromBase64String(parts[2]);
    }
    catch (FormatException exception)
    {
        throw new InvalidOperationException("Demo:PasswordHash has an invalid PBKDF2 format.", exception);
    }

    var suppliedHash = Rfc2898DeriveBytes.Pbkdf2(
        password, salt, iterations, HashAlgorithmName.SHA256, expectedHash.Length);
    return usernameMatches && CryptographicOperations.FixedTimeEquals(suppliedHash, expectedHash);
}

static Task<int> RevokeActiveTokens(
    AuthDbContext database,
    string userId,
    DateTime now,
    CancellationToken cancellationToken) =>
    database.RefreshTokens
        .Where(token => token.UserId == userId && token.RevokedAt == null)
        .ExecuteUpdateAsync(update => update.SetProperty(token => token.RevokedAt, now), cancellationToken);

static async Task<bool> VerifyAndConsumeTotpAsync(
    AuthDbContext database,
    string secret,
    string userId,
    string code,
    DateTime utcNow,
    CancellationToken cancellationToken)
{
    var matchingStep = Totp.FindMatchingStep(secret, code, utcNow);
    if (matchingStep is null)
    {
        return false;
    }

    var updated = await database.Database.ExecuteSqlInterpolatedAsync(
        $"""
        INSERT INTO TotpReplayStates (UserId, LastAcceptedStep)
        VALUES ({userId}, {matchingStep.Value})
        ON CONFLICT(UserId) DO UPDATE
        SET LastAcceptedStep = excluded.LastAcceptedStep
        WHERE TotpReplayStates.LastAcceptedStep < excluded.LastAcceptedStep
        """,
        cancellationToken);
    return updated == 1;
}

public sealed record LoginRequest(string Username, string Password, string? Code = null);
public sealed record TwoFactorRequest(string Username, string Password, string Code);
public sealed record RefreshRequest(string RefreshToken);
