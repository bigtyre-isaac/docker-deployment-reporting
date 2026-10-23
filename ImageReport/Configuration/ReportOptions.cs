namespace ImageReport.Configuration;

/// <summary>
/// Identifies the local Swarm in report results.
/// </summary>
public sealed class SwarmOptions
{
    /// <summary>
    /// The local deployment identifier included in each image and local error.
    /// </summary>
    public string Name { get; set; } = "local";
}

/// <summary>
/// Controls access to the local Docker Engine.
/// </summary>
public sealed class DockerOptions
{
    /// <summary>
    /// The Docker Engine socket or API address.
    /// </summary>
    public string Endpoint { get; set; } = "unix:///var/run/docker.sock";

    /// <summary>
    /// The maximum duration of a local Engine request.
    /// </summary>
    public int TimeoutSeconds { get; set; } = 30;
}

/// <summary>
/// Lists trusted report instances and limits outgoing request duration.
/// </summary>
public sealed class FederationOptions
{
    /// <summary>
    /// Trusted report origins that may receive the caller's bearer token.
    /// </summary>
    public List<FederationPeer> Peers { get; set; } = [];

    /// <summary>
    /// The maximum duration of each peer request, including its response body.
    /// </summary>
    public int TimeoutSeconds { get; set; } = 15;

    /// <summary>
    /// Explicitly permits plaintext HTTP to trusted internal development peers.
    /// </summary>
    public bool AllowHttp { get; set; }

    /// <summary>
    /// Rejects ambiguous URLs and insecure peers before any credentials can be forwarded.
    /// </summary>
    public bool IsValid()
    {
        var validOrigins = Peers.All(peer => !string.IsNullOrWhiteSpace(peer.Name)
            && Uri.TryCreate(peer.BaseUrl, UriKind.Absolute, out var uri)
            && (uri.Scheme == Uri.UriSchemeHttps || (AllowHttp && uri.Scheme == Uri.UriSchemeHttp))
            && string.IsNullOrEmpty(uri.UserInfo)
            && string.IsNullOrEmpty(uri.Query)
            && string.IsNullOrEmpty(uri.Fragment)
            && uri.AbsolutePath == "/");

        return validOrigins
            && Peers.Select(peer => peer.Name)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count() == Peers.Count;
    }
}

/// <summary>
/// A trusted instance whose origin is supplied only through server configuration.
/// </summary>
public sealed class FederationPeer
{
    /// <summary>
    /// The identifier used when reporting this peer's collection failures.
    /// </summary>
    public string Name { get; set; } = "";

    /// <summary>
    /// The trusted origin without a path, credentials, query, or fragment.
    /// </summary>
    public string BaseUrl { get; set; } = "";
}
