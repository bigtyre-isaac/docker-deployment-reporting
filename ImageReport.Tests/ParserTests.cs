using ImageReport.Utilities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ImageReport.Tests;

/// <summary>
/// Checks Docker reference boundaries without requiring a Docker daemon.
/// </summary>
[TestClass]
public sealed class ParserTests
{
    /// <summary>
    /// Preserves explicit components, including registry ports and combined tags and digests.
    /// </summary>
    [TestMethod]
    [DataRow("nginx", "nginx", null, null)]
    [DataRow("nginx:1.27", "nginx", "1.27", null)]
    [DataRow("registry:5000/team/nested/api", "registry:5000/team/nested/api", null, null)]
    [DataRow("registry:5000/team/api:v1", "registry:5000/team/api", "v1", null)]
    [DataRow("team/api@sha256:abc123", "team/api", null, "sha256:abc123")]
    [DataRow("registry.example.com/example/auth:1.2.3@sha256:abc123", "registry.example.com/example/auth", "1.2.3", "sha256:abc123")]
    [DataRow("[::1]:5000/team/api:v1@sha256:abc", "[::1]:5000/team/api", "v1", "sha256:abc")]
    public void ParsePreservesReference(string reference, string repository, string? tag, string? digest)
    {
        var result = DockerImageReferenceParser.Parse("production", "auth_api", reference);
        Assert.AreEqual(reference, result.Image);
        Assert.AreEqual(repository, result.Repository);
        Assert.AreEqual(tag, result.Tag);
        Assert.AreEqual(digest, result.Digest);
        Assert.AreEqual("production", result.Swarm);
        Assert.AreEqual("auth_api", result.Service);
    }
}
