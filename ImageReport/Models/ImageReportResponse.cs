namespace ImageReport.Models;

/// <summary>
/// Collected service images and failures from the requested Swarms.
/// </summary>
public sealed record ImageReportResponse(List<DeployedImage> Images, List<CollectionError> Errors);

/// <summary>
/// A collection failure identified by local Swarm or configured peer name.
/// </summary>
public sealed record CollectionError(string Swarm, string Message);
