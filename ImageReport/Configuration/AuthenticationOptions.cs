namespace ImageReport.Configuration;

/// <summary>
/// Configures requests to the authentication API.
/// </summary>
public sealed class AuthenticationOptions
{
    /// <summary>
    /// Authentication API base URL, including any path prefix and ending with a slash.
    /// </summary>
    public string ApiBaseUrl { get; set; } = "";

    /// <summary>
    /// Maximum duration of an authentication API request.
    /// </summary>
    public int ApiTimeoutSeconds { get; set; } = 15;

    /// <summary>
    /// Validates the authentication API URL and timeout.
    /// </summary>
    public bool IsValid(bool isDevelopment)
    {
        if (ApiTimeoutSeconds <= 0)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(ApiBaseUrl))
        {
            return true;
        }

        return Uri.TryCreate(ApiBaseUrl, UriKind.Absolute, out var uri)
            && (uri.Scheme == Uri.UriSchemeHttps
                || (isDevelopment
                    && uri.Scheme == Uri.UriSchemeHttp
                    && (uri.IsLoopback
                        || uri.Host.Equals("host.docker.internal", StringComparison.OrdinalIgnoreCase))))
            && string.IsNullOrEmpty(uri.UserInfo)
            && string.IsNullOrEmpty(uri.Query)
            && string.IsNullOrEmpty(uri.Fragment)
            && uri.AbsolutePath.EndsWith("/", StringComparison.Ordinal);
    }
}
