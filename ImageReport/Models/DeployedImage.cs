namespace ImageReport.Models;

/// <summary>
/// A service's deployment image and any matching Harbor vulnerability summary.
/// </summary>
public sealed record DeployedImage(string Swarm, string Service, string Image, string Repository, string? Tag, string? Digest)
{
    /// <summary>
    /// Indicates whether Harbor returned a completed vulnerability report or why counts are unknown.
    /// </summary>
    public string VulnerabilityScanStatus { get; init; } = "unknown";

    /// <summary>
    /// Explains why vulnerability counts are unknown; null when a report was retrieved.
    /// </summary>
    public string? VulnerabilityScanReason { get; init; }

    /// <summary>
    /// Critical vulnerability count, or null when no completed scan is available.
    /// </summary>
    public int? CriticalVulnerabilities { get; init; }

    /// <summary>
    /// High vulnerability count, or null when no completed scan is available.
    /// </summary>
    public int? HighVulnerabilities { get; init; }

    /// <summary>
    /// Medium vulnerability count, or null when no completed scan is available.
    /// </summary>
    public int? MediumVulnerabilities { get; init; }
}
