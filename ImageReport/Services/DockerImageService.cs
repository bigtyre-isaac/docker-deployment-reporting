using Docker.DotNet;
using Docker.DotNet.Models;
using ImageReport.Configuration;
using ImageReport.Models;
using ImageReport.Utilities;
using Microsoft.Extensions.Options;

namespace ImageReport.Services;

/// <summary>
/// Reads deployment references directly from local Swarm service specifications.
/// </summary>
public sealed class DockerImageService(IDockerClient docker, IOptions<SwarmOptions> options)
{
    /// <summary>
    /// Collects every service's configured image without inspecting task containers.
    /// </summary>
    public async Task<List<DeployedImage>> CollectAsync(CancellationToken cancellationToken)
    {
        var services = await docker.Swarm.ListServicesAsync(new ServicesListParameters(), cancellationToken);

        return services.Select(service => DockerImageReferenceParser.Parse(
            options.Value.Name,
            service.Spec.Name,
            service.Spec.TaskTemplate.ContainerSpec.Image)).ToList();
    }
}
