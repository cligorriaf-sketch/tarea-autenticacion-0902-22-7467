-- Run against the local-auth.db created by 01-local/api.
-- TokenHash contains SHA-256 hex digests, never refresh-token plaintext.
SELECT
    Id,
    UserId,
    TokenHash,
    length(TokenHash) AS HashLength,
    ExpiresAt,
    CreatedAt,
    RevokedAt,
    ReplacedByTokenId
FROM RefreshTokens
ORDER BY UserId, Id;

-- After reuse detection, every row for that UserId should have RevokedAt set.
SELECT
    UserId,
    COUNT(*) AS TotalTokens,
    SUM(CASE WHEN RevokedAt IS NULL THEN 1 ELSE 0 END) AS ActiveTokens,
    SUM(CASE WHEN RevokedAt IS NOT NULL THEN 1 ELSE 0 END) AS RevokedTokens
FROM RefreshTokens
GROUP BY UserId;
