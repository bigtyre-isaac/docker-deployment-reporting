using Docker.DotNet;
using ImageReport.Configuration;
using ImageReport.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);
var services = builder.Services;

// Swarm secrets use filenames such as Authentication__PublicKey as configuration keys.
var secretsDirectory = builder.Configuration["Secrets:Directory"] ?? "/run/secrets";
builder.Configuration.AddKeyPerFile(secretsDirectory, optional: true);

// Authentication configuration is required before the application can start.
var validationParameters = JwtConfiguration.CreateValidationParameters(builder.Configuration);

services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = true;
        options.IncludeErrorDetails = false;
        options.TokenValidationParameters = validationParameters;
    });

services.AddAuthorization();

// Validate collection settings at startup, before handling reporting requests.
services.AddOptions<SwarmOptions>()
    .BindConfiguration("Swarm")
    .Validate(options => !string.IsNullOrWhiteSpace(options.Name), "Swarm:Name is required.")
    .ValidateOnStart();

services.AddOptions<DockerOptions>()
    .BindConfiguration("Docker")
    .Validate(options => Uri.TryCreate(options.Endpoint, UriKind.Absolute, out var uri) && uri.Scheme is "unix" or "npipe" or "http" or "https","Docker:Endpoint must be a Docker Engine URI.")
    .Validate(
        options => options.TimeoutSeconds > 0,
        "Docker:TimeoutSeconds must be positive.")
    .ValidateOnStart();

services.AddOptions<FederationOptions>()
    .BindConfiguration("Federation")
    .Validate(options => options.TimeoutSeconds > 0,"Federation:TimeoutSeconds must be positive.")
    .Validate(options => options.IsValid(), "Federation peers must have unique names and trusted HTTPS origin URLs (or explicitly allowed HTTP).")
    .ValidateOnStart();

services.AddOptions<HarborOptions>()
    .BindConfiguration("Harbor")
    .Validate(options => options.IsValid(), "Harbor settings must use a trusted HTTPS origin, provide paired credentials, and use a positive timeout.")
    .ValidateOnStart();

// Reuse the local Docker client and create outgoing peer clients through the HTTP client factory.
services.AddSingleton<IDockerClient>(provider =>
{
    var options = provider.GetRequiredService<IOptions<DockerOptions>>().Value;
    var client = new DockerClientConfiguration(new Uri(options.Endpoint)).CreateClient();

    client.DefaultTimeout = TimeSpan.FromSeconds(options.TimeoutSeconds);

    return client;
});

services.AddHttpClient("Federation", (provider, client) =>
    {
        var options = provider.GetRequiredService<IOptions<FederationOptions>>().Value;
        client.Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds);
    })
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
    {
        // A redirected request must never forward the caller's credentials to another origin.
        AllowAutoRedirect = false,
        UseCookies = false
    });

services.AddHttpClient("Harbor", (provider, client) =>
    {
        var options = provider.GetRequiredService<IOptions<HarborOptions>>().Value;
        client.Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds);
    })
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false
    });

services.AddScoped<DockerImageService>();
services.AddScoped<FederationService>();
services.AddScoped<HarborVulnerabilityService>();

services.AddProblemDetails();
services.AddExceptionHandler<DockerExceptionHandler>();

var app = builder.Build();

app.UseExceptionHandler();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/images", async (
    bool? includeFederated,
    bool? includeVulnerabilities,
    HttpContext context,
    DockerImageService docker,
    FederationService federation,
    HarborVulnerabilityService harbor,
    CancellationToken cancellationToken) =>
{
    var localImages = await docker.CollectAsync(cancellationToken);
    var authorization = context.Request.Headers.Authorization.ToString();

    var report = await federation.AggregateAsync(
        localImages,
        includeFederated ?? true,
        authorization,
        cancellationToken);

    if (includeVulnerabilities ?? true)
    {
        var enrichedImages = await harbor.EnrichAsync(report.Images, cancellationToken);
        report = report with { Images = enrichedImages };
    }

    return Results.Ok(report);
}).RequireAuthorization(policy => policy.RequireRole("ImageReport.Read"));

app.Run();

/// <summary>
/// Application entry point, exposed for in-process endpoint verification.
/// </summary>
public partial class Program;
