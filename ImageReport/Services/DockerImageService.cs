using Docker.DotNet;
using Docker.DotNet.Models;
using ImageReport.Configuration;
using ImageReport.Models;
using ImageReport.Utilities;
using Microsoft.Extensions.Options;

namespace ImageReport.Services;

/// <summary>
/// Reads deployment references from local Swarm service specifications and local image metadata.
/// </summary>
public sealed class DockerImageService(IDockerClient docker, IOptions<SwarmOptions> options)
{
    /// <summary>
    /// Collects configured images and adds matching local image metadata when available.
    /// </summary>
    public async Task<List<DeployedImage>> CollectAsync(CancellationToken cancellationToken)
    {
        var services = await docker.Swarm.ListServicesAsync(new ServicesListParameters(), cancellationToken);
        var images = services.Select(service => DockerImageReferenceParser.Parse(
            options.Value.Name,
            service.Spec.Name,
            service.Spec.TaskTemplate.ContainerSpec.Image)).ToList();

        if (images.Count == 0)
        {
            return images;
        }

        var localImages = await docker.Images.ListImagesAsync(
            new ImagesListParameters { All = true },
            cancellationToken);
        var localImagesByTag = new Dictionary<string, ImagesListResponse>(StringComparer.Ordinal);

        foreach (var localImage in localImages)
        {
            foreach (var tag in localImage.RepoTags ?? [])
            {
                localImagesByTag.TryAdd(tag, localImage);
            }
        }

        return images.Select(image =>
        {
            var localImage = FindLocalImage(image, localImages, localImagesByTag);
            if (localImage is null)
            {
                return image;
            }

            return image with
            {
                LocalImageId = localImage.ID,
                LocalRepoDigest = GetLocalRepoDigest(localImage, image.Repository, image.Digest)
            };
        }).ToList();
    }

    /// <summary>
    /// Finds the local image referenced by a tag or repository digest.
    /// </summary>
    private static ImagesListResponse? FindLocalImage(
        DeployedImage image,
        IEnumerable<ImagesListResponse> localImages,
        IReadOnlyDictionary<string, ImagesListResponse> localImagesByTag)
    {
        if (image.Tag is not null)
        {
            var taggedReference = $"{image.Repository}:{image.Tag}";
            return localImagesByTag.GetValueOrDefault(taggedReference);
        }

        if (image.Digest is not null)
        {
            return localImages.FirstOrDefault(localImage =>
                (localImage.RepoDigests ?? []).Any(repoDigest =>
                    string.Equals(
                        GetRepository(repoDigest),
                        image.Repository,
                        StringComparison.Ordinal)
                    && string.Equals(
                        GetDigest(repoDigest),
                        image.Digest,
                        StringComparison.Ordinal)));
        }

        return localImagesByTag.GetValueOrDefault($"{image.Repository}:latest");
    }

    /// <summary>
    /// Selects the local digest for the deployed repository, preferring the deployed digest.
    /// </summary>
    private static string? GetLocalRepoDigest(
        ImagesListResponse localImage,
        string repository,
        string? preferredDigest)
    {
        var digests = (localImage.RepoDigests ?? [])
            .Where(repoDigest => string.Equals(
                GetRepository(repoDigest),
                repository,
                StringComparison.Ordinal))
            .Select(GetDigest)
            .ToList();

        return digests.FirstOrDefault(digest => digest == preferredDigest)
            ?? digests.FirstOrDefault();
    }

    /// <summary>
    /// Gets the repository part of a Docker repository digest.
    /// </summary>
    private static string GetRepository(string repoDigest)
    {
        var separator = repoDigest.LastIndexOf('@');
        return separator > 0 ? repoDigest[..separator] : string.Empty;
    }

    /// <summary>
    /// Gets the digest part of a Docker repository digest.
    /// </summary>
    private static string GetDigest(string repoDigest)
    {
        var separator = repoDigest.LastIndexOf('@');
        return separator > 0 ? repoDigest[(separator + 1)..] : string.Empty;
    }
}
