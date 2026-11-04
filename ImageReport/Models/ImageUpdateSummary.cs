namespace ImageReport.Models;

/// <summary>
/// Whether Harbor currently serves a different digest for the deployed image tag.
/// </summary>
/// <param name="Status">The result: upToDate, updateAvailable, or unknown.</param>
/// <param name="Reason">Why the comparison could not be completed, when applicable.</param>
/// <param name="CurrentDigest">The digest currently associated with the configured Harbor tag.</param>
/// <param name="Detail">Additional safe diagnostic detail, such as an HTTP status.</param>
public sealed record ImageUpdateSummary(
    string Status,
    string? Reason,
    string? CurrentDigest,
    string? Detail = null);
