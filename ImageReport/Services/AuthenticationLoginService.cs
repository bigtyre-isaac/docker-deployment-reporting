using System.IdentityModel.Tokens.Jwt;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using ImageReport.Configuration;
using ImageReport.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace ImageReport.Services;

/// <summary>
/// Exchanges user credentials for a validated JWT without exposing it to browser JavaScript.
/// </summary>
public sealed class AuthenticationLoginService(
    IHttpClientFactory clients,
    IOptions<AuthenticationOptions> options,
    TokenValidationParameters validationParameters,
    ILogger<AuthenticationLoginService> logger)
{
    private const string AuthenticationCookieName = "__Host-BigTyreAuth";

    /// <summary>
    /// Requests a JWT from the configured authentication service using BasicAuth credentials.
    /// </summary>
    public async Task<AuthenticationLoginResult> LoginAsync(
        LoginRequest login,
        CancellationToken cancellationToken)
    {
        var authApiBaseUrl = options.Value.ApiBaseUrl;

        if (string.IsNullOrWhiteSpace(authApiBaseUrl))
        {
            logger.LogWarning("Authentication service login cannot run because Authentication:ApiBaseUrl is not configured.");
            return AuthenticationLoginResult.Unavailable;
        }

        logger.LogInformation("Sending login request to the configured authentication service.");
        var authenticationUri = new Uri(new Uri(authApiBaseUrl), "auth/login");
        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            CredentialType = "BasicAuth",
            login.Username,
            login.Password
        });
        using var request = new HttpRequestMessage(HttpMethod.Post, authenticationUri)
        {
            Content = new ByteArrayContent(payload)
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        HttpResponseMessage response;

        try
        {
            response = await clients.CreateClient("Authentication")
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        }
        catch (HttpRequestException)
        {
            logger.LogWarning("Authentication service login request failed.");
            return AuthenticationLoginResult.Unavailable;
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning("Authentication service login request timed out.");
            return AuthenticationLoginResult.Unavailable;
        }

        using (response)
        {
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                logger.LogInformation("Authentication service rejected the supplied credentials.");
                return AuthenticationLoginResult.InvalidCredentials;
            }

            if (response.StatusCode == HttpStatusCode.Forbidden)
            {
                logger.LogInformation("Authentication service denied login access.");
                return AuthenticationLoginResult.Forbidden;
            }

            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning(
                    "Authentication service login failed with HTTP {StatusCode}.",
                    (int)response.StatusCode);
                return AuthenticationLoginResult.Unavailable;
            }

            var authenticationCookie = GetAuthenticationCookie(response.Headers);

            if (string.IsNullOrWhiteSpace(authenticationCookie?.Token))
            {
                logger.LogWarning("Authentication service response did not include its configured token cookie.");
                return AuthenticationLoginResult.Unavailable;
            }

            return ValidateToken(authenticationCookie.Token, authenticationCookie.Expires);
        }
    }

    private AuthenticationLoginResult ValidateToken(string token, DateTimeOffset? cookieExpires)
    {
        try
        {
            var principal = new JwtSecurityTokenHandler().ValidateToken(
                token,
                validationParameters,
                out var validatedToken);

            if (principal.Identity?.IsAuthenticated != true)
            {
                logger.LogWarning("Authentication service returned a token without an authenticated identity.");
                return AuthenticationLoginResult.Unavailable;
            }

            if (!principal.IsInRole("ImageReport.Read"))
            {
                logger.LogWarning("Authentication service returned a token without the ImageReport.Read role.");
                return AuthenticationLoginResult.Forbidden;
            }

            var expiry = validatedToken.ValidTo;

            if (expiry == DateTime.MinValue)
            {
                logger.LogWarning("Authentication service returned a token without an expiry.");
                return AuthenticationLoginResult.Unavailable;
            }

            var tokenExpires = new DateTimeOffset(DateTime.SpecifyKind(expiry, DateTimeKind.Utc));
            var effectiveExpiry = cookieExpires is not null && cookieExpires < tokenExpires
                ? cookieExpires.Value
                : tokenExpires;

            if (effectiveExpiry <= DateTimeOffset.UtcNow)
            {
                logger.LogWarning("Authentication service returned an expired token cookie.");
                return AuthenticationLoginResult.Unavailable;
            }

            logger.LogInformation("Authentication service token validated successfully.");
            return AuthenticationLoginResult.Success(token, effectiveExpiry);
        }
        catch (SecurityTokenException)
        {
            logger.LogWarning("Authentication service returned a token that failed local validation.");
            return AuthenticationLoginResult.Unavailable;
        }
        catch (ArgumentException)
        {
            logger.LogWarning("Authentication service returned a token that failed local validation.");
            return AuthenticationLoginResult.Unavailable;
        }
    }

    private static AuthenticationCookie? GetAuthenticationCookie(HttpResponseHeaders headers)
    {
        if (!headers.TryGetValues("Set-Cookie", out var setCookies))
        {
            return null;
        }

        var prefix = $"{AuthenticationCookieName}=";

        foreach (var setCookie in setCookies)
        {
            var attributes = setCookie.Split(';');
            var cookiePair = attributes[0].Trim();

            if (cookiePair.StartsWith(prefix, StringComparison.Ordinal))
            {
                var token = cookiePair[prefix.Length..].Trim().Trim('"');
                DateTimeOffset? expires = null;

                foreach (var attribute in attributes.Skip(1))
                {
                    var separator = attribute.IndexOf('=');

                    if (separator <= 0
                        || !attribute[..separator].Trim().Equals("expires", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    if (DateTimeOffset.TryParse(
                        attribute[(separator + 1)..].Trim(),
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                        out var parsedExpires))
                    {
                        expires = parsedExpires;
                    }

                    break;
                }

                return new AuthenticationCookie(token, expires);
            }
        }

        return null;
    }

    private sealed record AuthenticationCookie(string Token, DateTimeOffset? Expires);
}

/// <summary>
/// Result of an authentication service login exchange.
/// </summary>
public sealed record AuthenticationLoginResult(
    AuthenticationLoginStatus Status,
    string? Token,
    DateTimeOffset? Expires)
{
    /// <summary>
    /// The user credentials were rejected.
    /// </summary>
    public static AuthenticationLoginResult InvalidCredentials { get; } =
        new(AuthenticationLoginStatus.InvalidCredentials, null, null);

    /// <summary>
    /// The token is valid but does not grant access to the report.
    /// </summary>
    public static AuthenticationLoginResult Forbidden { get; } =
        new(AuthenticationLoginStatus.Forbidden, null, null);

    /// <summary>
    /// The authentication service could not provide a usable token.
    /// </summary>
    public static AuthenticationLoginResult Unavailable { get; } =
        new(AuthenticationLoginStatus.Unavailable, null, null);

    /// <summary>
    /// Creates a successful result containing the locally validated token.
    /// </summary>
    public static AuthenticationLoginResult Success(string token, DateTimeOffset expires) =>
        new(AuthenticationLoginStatus.Success, token, expires);
}

/// <summary>
/// Outcome categories for the authentication service exchange.
/// </summary>
public enum AuthenticationLoginStatus
{
    /// <summary>The authentication service issued a locally valid token.</summary>
    Success,

    /// <summary>The authentication service rejected the submitted credentials.</summary>
    InvalidCredentials,

    /// <summary>The issued token does not have the report access role.</summary>
    Forbidden,

    /// <summary>The authentication service was unavailable or returned an unusable token.</summary>
    Unavailable
}
