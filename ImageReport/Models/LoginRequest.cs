using System.ComponentModel.DataAnnotations;

namespace ImageReport.Models;

/// <summary>
/// Username and password submitted to begin a browser session.
/// </summary>
public sealed record LoginRequest
{
    /// <summary>
    /// Authentication service username.
    /// </summary>
    [Required]
    public required string Username { get; init; }

    /// <summary>
    /// Authentication service password.
    /// </summary>
    [Required]
    public required string Password { get; init; }
}
