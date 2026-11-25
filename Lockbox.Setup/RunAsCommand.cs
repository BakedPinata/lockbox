namespace Lockbox.Setup;

/// <summary>
/// Builds a <c>runas</c> command that starts the setup tool as another account, such as a scheduled task's account.
/// Credentials only decrypt for the account that saved them, so they must be saved as the account that runs the app.
/// </summary>
public static class RunAsCommand
{
    /// <summary>Builds the command.</summary>
    /// <param name="account">The account, for example <c>SERVER\jobaccount</c> or <c>DOMAIN\svc-export</c>.</param>
    /// <param name="setupToolPath">This tool's executable.</param>
    /// <param name="appPath">The app being set up.</param>
    /// <param name="secretsPath">A secrets path override, or <see langword="null"/> for the app's default.</param>
    /// <exception cref="ArgumentException">The account is blank or contains a quote.</exception>
    public static string Build(string account, string setupToolPath, string appPath, string? secretsPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(account);
        if (account.Contains('"', StringComparison.Ordinal))
        {
            throw new ArgumentException("The account name can't contain quotes.", nameof(account));
        }

        // runas takes the whole command line as one argument, so the inner quotes are escaped as \".
        var inner = $"\\\"{setupToolPath}\\\" --app \\\"{appPath}\\\"";
        if (!string.IsNullOrWhiteSpace(secretsPath))
        {
            inner += $" --secrets-path \\\"{secretsPath}\\\"";
        }

        return $"runas /user:{account.Trim()} \"{inner}\"";
    }
}
