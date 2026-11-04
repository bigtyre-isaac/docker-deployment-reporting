using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using ImageReport.Configuration;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ImageReport.Tests;

/// <summary>
/// Verifies RSA token compatibility and middleware rejection without contacting Docker.
/// </summary>
[TestClass]
public sealed class AuthenticationTests
{
    /// <summary>
    /// Standard role spellings map to ASP.NET roles even when a token has no audience.
    /// </summary>
    [TestMethod]
    [DataRow("role")]
    [DataRow("roles")]
    [DataRow(ClaimTypes.Role)]
    public void PublicKeyValidatesExistingRoleClaims(string claimType)
    {
        using var rsa = RSA.Create(2048);
        var configuration = Configuration(rsa.ExportSubjectPublicKeyInfoPem());
        var token = CreateToken(rsa, claimType, "ImageReport.Read", "issuer", false);
        var principal = new JwtSecurityTokenHandler().ValidateToken(token,
            JwtConfiguration.CreateValidationParameters(configuration), out _);
        Assert.IsTrue(principal.IsInRole("ImageReport.Read"));
    }

    /// <summary>
    /// Invalid signatures, issuers, lifetimes, and missing roles are rejected before Docker collection.
    /// </summary>
    [TestMethod]
    [DataRow("missing", 401)]
    [DataRow("wrong-key", 401)]
    [DataRow("wrong-issuer", 401)]
    [DataRow("expired", 401)]
    [DataRow("wrong-role", 403)]
    public async Task EndpointRejectsUnauthorizedRequests(string scenario, int expectedStatus)
    {
        using var trustedKey = RSA.Create(2048);
        using var otherKey = RSA.Create(2048);
        await using var app = new ReportApplication(trustedKey.ExportSubjectPublicKeyInfoPem());
        using var client = app.CreateClient();
        if (scenario != "missing")
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
                CreateToken(scenario == "wrong-key" ? otherKey : trustedKey, "role",
                    scenario == "wrong-role" ? "Other.Role" : "ImageReport.Read",
                    scenario == "wrong-issuer" ? "other" : "issuer", scenario == "expired"));
        }
        using var response = await client.GetAsync("/api/images");
        Assert.AreEqual((HttpStatusCode)expectedStatus, response.StatusCode);
    }

    /// <summary>
    /// Accepts the validated browser-session cookie through the JWT bearer authentication handler.
    /// </summary>
    [TestMethod]
    public async Task EndpointReadsJwtFromBrowserSessionCookie()
    {
        using var trustedKey = RSA.Create(2048);
        await using var app = new ReportApplication(trustedKey.ExportSubjectPublicKeyInfoPem());
        using var client = app.CreateClient();
        var token = CreateToken(trustedKey, "role", "Other.Role", "issuer", false);
        client.DefaultRequestHeaders.Add(
            "Cookie",
            $"{BrowserSessionCookie.Name}={token}");

        using var response = await client.GetAsync("/api/images");

        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// Missing, malformed, and private keys cannot produce a running authentication configuration.
    /// </summary>
    [TestMethod]
    public void AuthenticationConfigurationFailsClosed()
    {
        using var rsa = RSA.Create(2048);
        foreach (var key in new[] { "", "invalid", rsa.ExportPkcs8PrivateKeyPem() })
        {
            Assert.ThrowsExactly<InvalidOperationException>(() => JwtConfiguration.CreateValidationParameters(Configuration(key)));
        }
    }

    /// <summary>
    /// Loads PEM secrets through the real startup pipeline, with files taking precedence over other settings.
    /// </summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task StartupUsesKeyPerFilePublicKey(bool invalidSecret)
    {
        using var signingKey = RSA.Create(2048);
        using var otherKey = RSA.Create(2048);
        var directory = Directory.CreateTempSubdirectory("image-report-secrets-");

        try
        {
            var publicKey = invalidSecret ? "invalid" : signingKey.ExportSubjectPublicKeyInfoPem();
            await File.WriteAllTextAsync(Path.Combine(directory.FullName, "Authentication__PublicKey"), publicKey);

            // A different configured key must be replaced by the mounted file.
            await using var app = new ReportApplication(otherKey.ExportSubjectPublicKeyInfoPem(), directory.FullName);

            if (invalidSecret)
            {
                Assert.ThrowsExactly<InvalidOperationException>(() => app.CreateClient());
                return;
            }

            using var client = app.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
                CreateToken(signingKey, "role", "Other.Role", "issuer", false));

            using var response = await client.GetAsync("/api/images");

            // A valid signature with an insufficient role reaches authorization without accessing Docker.
            Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    /// <summary>
    /// Builds a token representing the existing issuer, deliberately omitting an audience.
    /// </summary>
    private static string CreateToken(RSA rsa, string claimType, string role, string issuer, bool expired)
    {
        var token = new JwtSecurityToken(issuer: issuer, claims: [new Claim(claimType, role)],
            notBefore: DateTime.UtcNow.AddHours(-1), expires: DateTime.UtcNow.AddMinutes(expired ? -5 : 5),
            signingCredentials: new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Creates test-only issuer settings using a generated public key.
    /// </summary>
    private static IConfiguration Configuration(string publicKey) => new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Authentication:Issuer"] = "issuer", ["Authentication:PublicKey"] = publicKey
        }).Build();

    /// <summary>
    /// Hosts the real authentication and authorization pipeline in memory.
    /// </summary>
    private sealed class ReportApplication(string publicKey, string? secretsDirectory = null) : WebApplicationFactory<Program>
    {
        /// <summary>
        /// Provides ephemeral authentication settings before application startup.
        /// </summary>
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseSetting("Authentication:Issuer", "issuer");
            builder.UseSetting("Authentication:PublicKey", publicKey);

            if (secretsDirectory is not null)
            {
                builder.UseSetting("Secrets:Directory", secretsDirectory);
            }
        }
    }
}
