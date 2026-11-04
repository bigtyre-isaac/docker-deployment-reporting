using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using ImageReport.Configuration;
using ImageReport.Models;
using ImageReport.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ImageReport.Tests;

/// <summary>
/// Tests the server-side exchange with the configured authentication service.
/// </summary>
[TestClass]
public sealed class AuthenticationLoginTests
{
    /// <summary>
    /// Permits Docker Desktop's HTTP host gateway only with the explicit development opt-in.
    /// </summary>
    [TestMethod]
    public void AuthenticationApiBaseUrlAllowsHttpOnlyForApprovedDevelopmentHosts()
    {
        Assert.IsFalse(new AuthenticationOptions
        {
            ApiBaseUrl = "http://host.docker.internal:44122/api/"
        }.IsValid(isDevelopment: false));

        Assert.IsTrue(new AuthenticationOptions
        {
            ApiBaseUrl = "http://host.docker.internal:44122/api/"
        }.IsValid(isDevelopment: true));

        Assert.IsFalse(new AuthenticationOptions
        {
            ApiBaseUrl = "http://host.docker.internal:44122/api",
        }.IsValid(isDevelopment: true));

        Assert.IsFalse(new AuthenticationOptions
        {
            ApiBaseUrl = "http://auth.example.com/api/"
        }.IsValid(isDevelopment: true));

        Assert.IsFalse(new AuthenticationOptions
        {
            ApiTimeoutSeconds = 0
        }.IsValid(isDevelopment: true));
    }

    /// <summary>
    /// Sends BasicAuth credentials to the configured endpoint and validates its returned token.
    /// </summary>
    [TestMethod]
    public async Task LoginSendsBasicAuthPayloadAndAcceptsValidReportToken()
    {
        using var signingKey = RSA.Create(2048);
        var token = CreateToken(signingKey, "ImageReport.Read");
        HttpMethod? receivedMethod = null;
        string? receivedUrl = null;
        string? receivedContentType = null;
        string? receivedBody = null;
        var upstreamCookieExpires = DateTimeOffset.UtcNow.AddMinutes(2);
        var factory = new StubHttpClientFactory((request, _) =>
        {
            receivedMethod = request.Method;
            receivedUrl = request.RequestUri!.ToString();
            receivedContentType = request.Content!.Headers.ContentType!.MediaType;
            receivedBody = request.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            var response = new HttpResponseMessage(HttpStatusCode.OK);
            response.Headers.TryAddWithoutValidation(
                "Set-Cookie",
                $"__Host-BigTyreAuth={token}; Expires={upstreamCookieExpires.UtcDateTime.ToString("R", System.Globalization.CultureInfo.InvariantCulture)}; Path=/; Secure; SameSite=Lax; HttpOnly");
            return Task.FromResult(response);
        });
        var service = CreateService(factory, signingKey);

        var result = await service.LoginAsync(
            new LoginRequest { Username = "report-user", Password = "test-password" },
            CancellationToken.None);

        Assert.AreEqual(HttpMethod.Post, receivedMethod);
        Assert.AreEqual("https://auth.example.com/api/auth/login", receivedUrl);
        Assert.AreEqual("application/json", receivedContentType);

        using var payload = JsonDocument.Parse(receivedBody!);
        var root = payload.RootElement;
        Assert.AreEqual("BasicAuth", root.GetProperty("CredentialType").GetString());
        Assert.AreEqual("report-user", root.GetProperty("Username").GetString());
        Assert.AreEqual("test-password", root.GetProperty("Password").GetString());

        Assert.AreEqual(AuthenticationLoginStatus.Success, result.Status);
        Assert.AreEqual(token, result.Token);
        Assert.IsNotNull(result.Expires);
        Assert.IsTrue(result.Expires <= upstreamCookieExpires);
    }

    /// <summary>
    /// Refuses tokens without the report role before they can become a browser session.
    /// </summary>
    [TestMethod]
    public async Task LoginRejectsTokenWithoutReportRole()
    {
        using var signingKey = RSA.Create(2048);
        var token = CreateToken(signingKey, "Other.Role");
        var factory = new StubHttpClientFactory((_, _) =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK);
            response.Headers.TryAddWithoutValidation(
                "Set-Cookie",
                $"__Host-BigTyreAuth={token}; Path=/; Secure; HttpOnly");
            return Task.FromResult(response);
        });
        var service = CreateService(factory, signingKey);

        var result = await service.LoginAsync(
            new LoginRequest { Username = "report-user", Password = "test-password" },
            CancellationToken.None);

        Assert.AreEqual(AuthenticationLoginStatus.Forbidden, result.Status);
        Assert.IsNull(result.Token);
    }

    /// <summary>
    /// Treats an upstream unauthorized response as rejected credentials.
    /// </summary>
    [TestMethod]
    public async Task LoginMapsAuthenticationUnauthorizedToInvalidCredentials()
    {
        using var signingKey = RSA.Create(2048);
        var factory = new StubHttpClientFactory((_, _) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized)));
        var service = CreateService(factory, signingKey);

        var result = await service.LoginAsync(
            new LoginRequest { Username = "report-user", Password = "bad-password" },
            CancellationToken.None);

        Assert.AreEqual(AuthenticationLoginStatus.InvalidCredentials, result.Status);
    }

    private static AuthenticationLoginService CreateService(
        IHttpClientFactory factory,
        RSA signingKey)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Authentication:Issuer"] = "Example Authentication API",
                ["Authentication:PublicKey"] = signingKey.ExportSubjectPublicKeyInfoPem()
            })
            .Build();

        return new AuthenticationLoginService(
            factory,
            Options.Create(new AuthenticationOptions
            {
                ApiBaseUrl = "https://auth.example.com/api/"
            }),
            JwtConfiguration.CreateValidationParameters(configuration),
            NullLogger<AuthenticationLoginService>.Instance);
    }

    private static string CreateToken(RSA signingKey, string role)
    {
        var token = new JwtSecurityToken(
            issuer: "Example Authentication API",
            claims: [new Claim("role", role)],
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(
                new RsaSecurityKey(signingKey),
                SecurityAlgorithms.RsaSha256));

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private sealed class StubHttpClientFactory(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> sendAsync) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(new StubHttpMessageHandler(sendAsync), disposeHandler: true);
    }

    private sealed class StubHttpMessageHandler(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> sendAsync)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            sendAsync(request, cancellationToken);
    }
}
