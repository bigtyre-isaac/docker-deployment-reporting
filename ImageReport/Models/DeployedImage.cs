namespace ImageReport.Models;

/// <summary>
/// A service's deployment image, preserving the exact Swarm specification reference.
/// </summary>
public sealed record DeployedImage(string Swarm, string Service, string Image, string Repository, string? Tag, string? Digest);
