using ImageReport.Configuration;
using ImageReport.Models;
using ImageReport.Services;

namespace ImageReport.Endpoints;

/// <summary>
/// Maps the browser authentication endpoints.
/// </summary>
public static class AuthenticationRoutes
{
    /// <summary>
    /// Maps login and logout routes.
    /// </summary>
    public static RouteGroupBuilder MapAuthenticationRoutes(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/auth");

        group.MapPost("/login", LoginAsync)
            .AllowAnonymous()
            .WithSummary("Sign in to the report")
            .WithDescription("Exchanges username and password with the configured authentication service and sets a validated HttpOnly session cookie.");

        group.MapPost("/logout", Logout)
            .AllowAnonymous()
            .WithSummary("Sign out of the report");

        return group;
    }

    private static async Task<IResult> LoginAsync(
        LoginRequest login,
        HttpContext context,
        AuthenticationLoginService authentication,
        CancellationToken cancellationToken)
    {
        context.Response.Headers.CacheControl = "no-store";
        var result = await authentication.LoginAsync(login, cancellationToken);

        if (result.Status == AuthenticationLoginStatus.InvalidCredentials)
        {
            return Results.Unauthorized();
        }

        if (result.Status == AuthenticationLoginStatus.Forbidden)
        {
            return Results.Forbid();
        }

        if (result.Status == AuthenticationLoginStatus.Unavailable)
        {
            return Results.Problem(
                statusCode: StatusCodes.Status502BadGateway,
                title: "Authentication service unavailable",
                detail: "The authentication service did not return a valid report-access token.");
        }

        context.Response.Cookies.Append(
            BrowserSessionCookie.Name,
            result.Token!,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/",
                Expires = result.Expires
            });

        return Results.NoContent();
    }

    private static IResult Logout(HttpContext context)
    {
        context.Response.Cookies.Delete(
            BrowserSessionCookie.Name,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/"
            });

        return Results.NoContent();
    }
}
