namespace ImageReport.Configuration;

/// <summary>
/// Defines the HttpOnly cookie used by the browser login flow.
/// </summary>
public static class BrowserSessionCookie
{
    /// <summary>
    /// Name of the local session cookie containing the validated JWT.
    /// </summary>
    public const string Name = "__Host-ImageReportSession";
}
