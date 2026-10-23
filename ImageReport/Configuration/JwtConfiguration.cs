using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace ImageReport.Configuration;

/// <summary>
/// Builds fail-closed RSA validation settings for externally issued JWTs.
/// </summary>
public static class JwtConfiguration
{
    /// <summary>
    /// Requires an issuer and PEM public key; never accepts a private signing key.
    /// </summary>
    public static TokenValidationParameters CreateValidationParameters(IConfiguration configuration)
    {
        var issuer = configuration["Authentication:Issuer"];
        var publicKey = configuration["Authentication:PublicKey"];

        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(publicKey))
        {
            throw new InvalidOperationException("Authentication:Issuer and Authentication:PublicKey are required.");
        }

        using var rsa = RSA.Create();

        try
        {
            if ((!publicKey.Contains("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal)
                && !publicKey.Contains("-----BEGIN RSA PUBLIC KEY-----", StringComparison.Ordinal))
                || publicKey.Contains("PRIVATE KEY", StringComparison.Ordinal))
            {
                throw new CryptographicException();
            }

            rsa.ImportFromPem(publicKey);

            if (rsa.KeySize < 2048)
            {
                throw new CryptographicException();
            }
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException)
        {
            throw new InvalidOperationException("Authentication:PublicKey must be a valid RSA public PEM key of at least 2048 bits.");
        }

        return new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new RsaSecurityKey(rsa.ExportParameters(false)),
            ValidAlgorithms =
            [
                SecurityAlgorithms.RsaSha256,
                SecurityAlgorithms.RsaSha384,
                SecurityAlgorithms.RsaSha512,
                SecurityAlgorithms.RsaSsaPssSha256,
                SecurityAlgorithms.RsaSsaPssSha384,
                SecurityAlgorithms.RsaSsaPssSha512
            ],

            ValidateIssuer = true,
            ValidIssuer = issuer,

            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ClockSkew = TimeSpan.FromSeconds(30),

            // Existing issuer tokens do not yet include an audience claim.
            ValidateAudience = false,
            RoleClaimType = ClaimTypes.Role
        };
    }
}
