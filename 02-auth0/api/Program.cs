using System.Collections.Concurrent;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);
var domain = builder.Configuration["Auth0:Domain"];
var audience = builder.Configuration["Auth0:Audience"];
if (string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(audience))
{
    throw new InvalidOperationException("Set Auth0:Domain and Auth0:Audience with User Secrets.");
}

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.Authority = $"https://{domain}/";
        options.Audience = audience;
    });
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("read:messages", policy =>
        policy.RequireAuthenticatedUser().RequireAssertion(context =>
            HasPermission(context.User, "read:messages")));
    options.AddPolicy("delete:messages", policy =>
        policy.RequireAuthenticatedUser().RequireAssertion(context =>
            HasPermission(context.User, "delete:messages")));
});
builder.Services.AddCors(options => options.AddDefaultPolicy(policy =>
    policy.WithOrigins("http://localhost:5174").AllowAnyHeader().AllowAnyMethod()));

var app = builder.Build();
var messages = new ConcurrentDictionary<int, Message>(new Dictionary<int, Message>
{
    [1] = new(1, "Bienvenida al curso", "profesor"),
    [2] = new(2, "Apuntes de seguridad", "estudiante")
});

app.UseRouting();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/messages", () => Results.Ok(messages.Values.OrderBy(message => message.Id)))
    .RequireAuthorization("read:messages");

app.MapDelete("/api/messages/{id:int}", (int id, ClaimsPrincipal user, ILogger<Program> logger) =>
{
    if (!messages.TryRemove(id, out _))
    {
        return Results.NotFound();
    }

    var userId = user.FindFirst("sub")?.Value;
    logger.LogInformation("Usuario {UserId} eliminó el mensaje {MessageId}", userId, id);
    return Results.Ok(new { deleted = id });
}).RequireAuthorization("delete:messages");

app.MapGet("/api/health", () => Results.Ok(new { status = "ok" }));
app.Run();

static bool HasPermission(ClaimsPrincipal user, string permission) =>
    user.FindAll("permissions").Any(claim => string.Equals(claim.Value, permission, StringComparison.Ordinal));

public sealed record Message(int Id, string Text, string CreatedBy);
