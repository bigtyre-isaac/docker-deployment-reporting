using ImageReport.Models;

namespace ImageReport.Utilities;

/// <summary>
/// Splits Docker references without normalizing registries or inventing tags.
/// </summary>
public static class DockerImageReferenceParser
{
    /// <summary>
    /// Separates a service reference into repository, explicit tag, and digest.
    /// </summary>
    public static DeployedImage Parse(string swarm, string service, string image)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(image);

        var digestSeparator = image.IndexOf('@');
        var repositoryAndTag = digestSeparator >= 0 ? image[..digestSeparator] : image;
        var digest = digestSeparator >= 0 ? image[(digestSeparator + 1)..] : null;

        // A colon before the final slash belongs to the registry port, not the image tag.
        var tagSeparator = repositoryAndTag.LastIndexOf(':');
        var hasTag = tagSeparator > repositoryAndTag.LastIndexOf('/');
        var repository = hasTag ? repositoryAndTag[..tagSeparator] : repositoryAndTag;
        var tag = hasTag ? repositoryAndTag[(tagSeparator + 1)..] : null;

        return new DeployedImage(swarm, service, image, repository, tag, digest);
    }
}
