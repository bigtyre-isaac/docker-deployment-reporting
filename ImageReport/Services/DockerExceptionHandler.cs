using Docker.DotNet;
using ImageReport.Configuration;
using ImageReport.Models;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.Extensions.Options;

namespace ImageReport.Services;

/// <summary>
/// Translates local Docker transport and API failures into safe, Swarm-identified responses.
/// </summary>
public sealed class DockerExceptionHandler(
    IOptions<SwarmOptions> options,
    ILogger<DockerExceptionHandler> logger) : IExceptionHandler
{
    /// <summary>
    /// Returns 503 for an unavailable engine and 502 for other Docker API failures.
    /// </summary>
    public async ValueTask<bool> TryHandleAsync(
        HttpContext context,
        Exception exception,
        CancellationToken cancellationToken)
    {
        if (context.RequestAborted.IsCancellationRequested)
        {
            return false;
        }

        var status = exception switch
        {
            DockerApiException api => (int)api.StatusCode >= 500
                ? StatusCodes.Status503ServiceUnavailable
                : StatusCodes.Status502BadGateway,
            HttpRequestException or IOException or System.Net.Sockets.SocketException or TimeoutException
                or OperationCanceledException => StatusCodes.Status503ServiceUnavailable,
            _ => 0
        };

        if (status == 0)
        {
            return false;
        }

        logger.LogWarning(
            "Local Docker collection failed for {Swarm} ({FailureType})",
            options.Value.Name,
            exception.GetType().Name);

        var message = status == StatusCodes.Status503ServiceUnavailable
            ? "Local Docker daemon is unavailable."
            : "Local Docker API rejected the service query.";

        var report = new ImageReportResponse([], [new(options.Value.Name, message)]);

        context.Response.StatusCode = status;
        await context.Response.WriteAsJsonAsync(report, cancellationToken);

        return true;
    }
}
