using System.Security.Cryptography;

namespace LocalAuth.Api.Services;

public static class Totp
{
    public static bool Verify(string secret, string suppliedCode, DateTime utcNow)
        => FindMatchingStep(secret, suppliedCode, utcNow) is not null;

    public static long? FindMatchingStep(string secret, string suppliedCode, DateTime utcNow)
    {
        if (string.IsNullOrEmpty(suppliedCode)
            || suppliedCode.Length != 6
            || !suppliedCode.All(char.IsAsciiDigit))
        {
            return null;
        }

        var key = DecodeBase32(secret);
        var currentStep = new DateTimeOffset(utcNow).ToUnixTimeSeconds() / 30;
        for (var offset = -1; offset <= 1; offset++)
        {
            var matchingStep = currentStep + offset;
            if (matchingStep < 0)
            {
                continue;
            }

            var counter = BitConverter.GetBytes(
                System.Net.IPAddress.HostToNetworkOrder(matchingStep));
            var digest = HMACSHA1.HashData(key, counter);
            var index = digest[^1] & 0x0f;
            var binaryCode = ((digest[index] & 0x7f) << 24)
                | (digest[index + 1] << 16)
                | (digest[index + 2] << 8)
                | digest[index + 3];
            var expected = (binaryCode % 1_000_000).ToString("D6");
            if (CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.ASCII.GetBytes(expected),
                System.Text.Encoding.ASCII.GetBytes(suppliedCode)))
            {
                return matchingStep;
            }
        }

        return null;
    }

    private static byte[] DecodeBase32(string value)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var output = new List<byte>();
        var buffer = 0;
        var bitsInBuffer = 0;
        foreach (var character in value.TrimEnd('=').ToUpperInvariant())
        {
            var digit = alphabet.IndexOf(character);
            if (digit < 0)
            {
                throw new FormatException("The configured TOTP secret must be Base32.");
            }

            buffer = (buffer << 5) | digit;
            bitsInBuffer += 5;
            if (bitsInBuffer >= 8)
            {
                bitsInBuffer -= 8;
                output.Add((byte)(buffer >> bitsInBuffer));
            }
        }

        return output.ToArray();
    }
}
