using System.Net.Http.Headers;
using System.Text.Json;
using ImageReport.Configuration;
using ImageReport.Models;
using Microsoft.Extensions.Options;

namespace ImageReport.Services;

/// <summary>
/// Aggregates local results with independent, non-recursive requests to trusted peers.
/// </summary>
public sealed class FederationService(
    IHttpClientFactory clients,
    IOptions<FederationOptions> options,
    ILogger<FederationService> logger)
{
    /// <summary>
    /// Queries peers concurrently when requested and sorts the complete report deterministically.
    /// </summary>
    public async Task<ImageReportResponse> AggregateAsync(
        List<DeployedImage> localImages,
        bool includeFederated,
        string authorization,
        CancellationToken cancellationToken)
    {
        var report = new ImageReportResponse([.. localImages], []);

        if (includeFederated)
        {
            var results = await Task.WhenAll(options.Value.Peers.Select(peer =>
                CollectPeerAsync(peer, authorization, cancellationToken)));

            foreach (var result in results)
            {
                report.Images.AddRange(result.Images);
                report.Errors.AddRange(result.Errors);
            }
        }

        report.Images.Sort((left, right) =>
        {
            var swarmOrder = StringComparer.Ordinal.Compare(left.Swarm, right.Swarm);

            return swarmOrder != 0
                ? swarmOrder
                : StringComparer.Ordinal.Compare(left.Service, right.Service);
        });

        return report;
    }

    /// <summary>
    /// Forwards the caller's bearer header only to one configured origin and isolates peer failures.
    /// </summary>
    private async Task<ImageReportResponse> CollectPeerAsync(
        FederationPeer peer,
        string authorization,
        CancellationToken cancellationToken)
    {
        try
        {
            using var client = clients.CreateClient("Federation");
            using var request = new HttpRequestMessage(HttpMethod.Get,
                new Uri(new Uri(peer.BaseUrl), "/api/images?includeFederated=false&includeVulnerabilities=false"));

            request.Headers.Authorization = AuthenticationHeaderValue.Parse(authorization);

            using var response = await client.SendAsync(request, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning(
                    "Image collection from peer {Peer} returned HTTP {StatusCode}",
                    peer.Name,
                    (int)response.StatusCode);

                return new ImageReportResponse([], [new(peer.Name, $"Peer returned HTTP {(int)response.StatusCode}.")]);
            }

            var report = await response.Content.ReadFromJsonAsync<ImageReportResponse>(cancellationToken);

            if (report is null
                || report.Images is null
                || report.Errors is null
                || report.Images.Any(image => image is null
                    || string.IsNullOrWhiteSpace(image.Swarm)
                    || string.IsNullOrWhiteSpace(image.Service)
                    || string.IsNullOrWhiteSpace(image.Image)
                    || string.IsNullOrWhiteSpace(image.Repository))
                || report.Errors.Any(error => error is null || string.IsNullOrWhiteSpace(error.Message)))
            {
                throw new JsonException("Peer response does not contain a valid report envelope.");
            }

            // Remote service names remain authoritative, but failures identify the configured peer.
            var errors = report.Errors
                .Select(error => new CollectionError(peer.Name, error.Message))
                .ToList();

            return new ImageReportResponse(report.Images, errors);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning("Image collection from peer {Peer} timed out", peer.Name);

            return new ImageReportResponse([], [new(peer.Name, "Peer request timed out.")]);
        }
        catch (Exception exception) when (exception is HttpRequestException or JsonException or NotSupportedException)
        {
            // Do not log exception messages: peer responses and URLs may contain sensitive data.
            logger.LogWarning(
                "Image collection from peer {Peer} failed ({FailureType})",
                peer.Name,
                exception.GetType().Name);

            return new ImageReportResponse([], [new(peer.Name, "Peer request failed or returned an invalid report.")]);
        }
    }
}
