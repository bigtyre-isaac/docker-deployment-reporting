namespace ImageReport.Models;

/// <summary>
/// A service's deployment image and any matching Harbor vulnerability summary.
/// </summary>
public sealed record DeployedImage(string Swarm, string Service, string Image, string Repository, string? Tag, string? Digest)
{
    /// <summary>
    /// Local Docker image ID when the configured image reference exists on this daemon.
    /// </summary>
    public string? LocalImageId { get; init; }

    /// <summary>
    /// Local repository digest matching the deployed repository, when available.
    /// </summary>
    public string? LocalRepoDigest { get; init; }

    /// <summary>
    /// Vulnerability scan status, reason, and counts by severity.
    /// </summary>
    public VulnerabilitySummary Vulnerabilities { get; init; } = new(
        "unknown",
        null,
        new VulnerabilityCounts(null, null, null, null, null));
}
