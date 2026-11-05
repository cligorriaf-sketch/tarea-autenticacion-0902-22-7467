namespace LocalAuth.Api.Models;

public sealed class TotpReplayState
{
    public required string UserId { get; set; }
    public long LastAcceptedStep { get; set; }
}
