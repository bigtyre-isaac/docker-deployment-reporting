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
    /// Collects each configured image and adds its local image ID when the reference is available.
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
        var localImageIdsByTag = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var localImage in localImages)
        {
            foreach (var tag in localImage.RepoTags ?? [])
            {
                localImageIdsByTag.TryAdd(tag, localImage.ID);
            }
        }

        return images.Select(image =>
            localImageIdsByTag.TryGetValue(image.Image, out var localImageId)
                ? image with { LocalImageId = localImageId }
                : image).ToList();
    }
}
