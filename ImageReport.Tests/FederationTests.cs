using System.Net;
using System.Net.Http.Json;
using ImageReport.Configuration;
using ImageReport.Models;
using ImageReport.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ImageReport.Tests;

/// <summary>
/// Verifies federation isolation, credential forwarding, concurrency, and cancellation with in-memory HTTP.
/// </summary>
[TestClass]
public sealed class FederationTests
{
    /// <summary>
    /// Successful peers survive another peer's failure and returned Swarm names remain authoritative.
    /// </summary>
    [TestMethod]
    public async Task AggregationForwardsBearerDisablesRecursionAndPreservesPartialResults()
    {
        var arrived = 0;
        var bothArrived = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var factory = new StubHttpFactory(async (request, token) =>
        {
            Assert.AreEqual(
                "/api/images?includeFederated=false&includeVulnerabilities=false&includeImageUpdates=false",
                request.RequestUri!.PathAndQuery);
            Assert.AreEqual("Bearer test-token", request.Headers.Authorization!.ToString());
            if (Interlocked.Increment(ref arrived) == 2)
            {
                bothArrived.SetResult();
            }
            await bothArrived.Task.WaitAsync(token);
            return request.RequestUri.Host == "broken.internal"
                ? new HttpResponseMessage(HttpStatusCode.Forbidden)
                : new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(new ImageReportResponse(
                        [new("actual-remote", "z", "api", "api", null, null), new("actual-remote", "a", "api:v1", "api", "v1", null)], []))
                };
        });
        var service = CreateService(factory);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var report = await service.AggregateAsync([new("local", "api", "api", "api", null, null)], true, "Bearer test-token", timeout.Token);
        Assert.AreEqual(3, report.Images.Count);
        Assert.AreEqual("actual-remote", report.Images[0].Swarm);
        Assert.AreEqual("a", report.Images[0].Service);
        Assert.AreEqual("broken", report.Errors.Single().Swarm);
    }

    /// <summary>
    /// Local-only mode never contacts configured peers.
    /// </summary>
    [TestMethod]
    public async Task LocalOnlySkipsPeers()
    {
        var service = CreateService(new StubHttpFactory((_, _) => throw new AssertFailedException("Unexpected peer request.")));
        var report = await service.AggregateAsync([], false, "", CancellationToken.None);
        Assert.AreEqual(0, report.Errors.Count);
    }

    /// <summary>
    /// Invalid JSON and peer timeouts become errors identified by configured peer names.
    /// </summary>
    [TestMethod]
    public async Task InvalidResponsesAndTimeoutsAreIsolated()
    {
        var service = CreateService(new StubHttpFactory((request, _) =>
        {
            if (request.RequestUri!.Host == "broken.internal")
            {
                throw new TaskCanceledException("Simulated HttpClient timeout.");
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") });
        }));
        var report = await service.AggregateAsync([], true, "Bearer token", CancellationToken.None);
        Assert.AreEqual(2, report.Errors.Count);
        Assert.AreEqual("remote", report.Errors[0].Swarm);
        Assert.AreEqual("broken", report.Errors[1].Swarm);
    }

    /// <summary>
    /// Request cancellation propagates instead of becoming a partial success.
    /// </summary>
    [TestMethod]
    public async Task CallerCancellationPropagates()
    {
        var service = CreateService(new StubHttpFactory(async (_, token) =>
        {
            await Task.Delay(Timeout.Infinite, token);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }));
        using var cancellation = new CancellationTokenSource();
        var task = service.AggregateAsync([], true, "Bearer token", cancellation.Token);
        cancellation.Cancel();
        await Assert.ThrowsExactlyAsync<TaskCanceledException>(() => task);
    }

    /// <summary>
    /// Restricts trusted origins and requires explicit opt-in for development HTTP.
    /// </summary>
    [TestMethod]
    public void PeerConfigurationRejectsUnsafeOrigins()
    {
        foreach (var url in new[] { "http://peer.internal", "https://user:pass@peer.internal", "https://peer.internal/path", "https://peer.internal?query", "file:///tmp/report" })
        {
            Assert.IsFalse(new FederationOptions { Peers = [new() { Name = "peer", BaseUrl = url }] }.IsValid());
        }
        Assert.IsTrue(new FederationOptions { AllowHttp = true, Peers = [new() { Name = "peer", BaseUrl = "http://peer.internal" }] }.IsValid());
    }

    /// <summary>
    /// Creates a real aggregator with two configured peers and an in-memory transport.
    /// </summary>
    private static FederationService CreateService(IHttpClientFactory factory)
    {
        return new FederationService(factory, Options.Create(new FederationOptions
        {
            Peers = [new() { Name = "remote", BaseUrl = "https://remote.internal" }, new() { Name = "broken", BaseUrl = "https://broken.internal" }]
        }), NullLogger<FederationService>.Instance);
    }

    /// <summary>
    /// Supplies disposable clients backed by a controlled transport.
    /// </summary>
    private sealed class StubHttpFactory(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : IHttpClientFactory
    {
        /// <summary>
        /// Creates a client without a network connection.
        /// </summary>
        public HttpClient CreateClient(string name) => new(new StubHandler(send));
    }

    /// <summary>
    /// Dispatches requests to test behavior without sockets or external peers.
    /// </summary>
    private sealed class StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        /// <summary>
        /// Passes the request and cancellation through to the test.
        /// </summary>
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken);
    }
}
