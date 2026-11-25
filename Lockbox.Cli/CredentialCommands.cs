using System.Buffers;
using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Lockbox.Cli;

/// <summary>
/// Adds <c>set-credentials</c>, <c>verify-credentials</c> and <c>show-credentials-info</c> to a console app.
/// </summary>
/// <example>
/// <code>
/// var credentials = new CredentialCommands("JiraExport", [new("jira.pat", "Jira personal access token")]);
/// if (await credentials.TryRunAsync(args) is int exitCode)
/// {
///     return exitCode;
/// }
///
/// var pat = credentials.CreateStore(args).GetSecret("jira.pat");
/// </code>
/// </example>
/// <remarks>
/// Secrets are only ever entered at a prompt (masked), never accepted as command-line arguments, because
/// arguments end up in shell history and process listings. No command prints a secret value.
/// Run the commands as the Windows account that will run the app: only that account can decrypt the secrets.
/// </remarks>
public sealed class CredentialCommands
{
    /// <summary>Prompts for each credential, encrypts and saves them, then verifies them.</summary>
    public const string SetCommand = "set-credentials";

    /// <summary>Checks that each credential decrypts and, if configured, that the service accepts them.</summary>
    public const string VerifyCommand = "verify-credentials";

    /// <summary>Shows the file path, who encrypted it, and secret names and dates, without decrypting.</summary>
    public const string InfoCommand = "show-credentials-info";

    /// <summary>
    /// Prints the app's name, secrets file path and credential definitions as JSON, so a setup tool such as
    /// Lockbox.Setup can save the app's credentials without knowing about the app in advance. No values are printed.
    /// </summary>
    public const string DescribeCommand = "describe-credentials";

    /// <summary>The <c>"format"</c> value of <see cref="DescribeCommand"/>'s output.</summary>
    public const string DescribeFormat = "lockbox-credentials/1";

    /// <summary>The option that overrides the secrets file path, as <c>--secrets-path &lt;path&gt;</c> or <c>--secrets-path=&lt;path&gt;</c>.</summary>
    public const string SecretsPathOption = "--secrets-path";

    /// <summary>The command succeeded.</summary>
    public const int ExitSuccess = 0;

    /// <summary>The command ran but failed, for example a secret didn't decrypt or the user cancelled.</summary>
    public const int ExitFailure = 1;

    /// <summary>The command line was invalid.</summary>
    public const int ExitUsage = 2;

    private readonly IConsoleIO _console;
    private readonly Func<string?, SecretStore> _storeFactory;
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates the commands for an app.</summary>
    /// <param name="appName">The app name passed to <see cref="SecretStore"/>. Keep it the same across releases.</param>
    /// <param name="credentials">The credentials the app needs, in prompt order.</param>
    public CredentialCommands(string appName, IEnumerable<CredentialDefinition> credentials)
        : this(appName, credentials, SystemConsoleIO.Instance, null, TimeProvider.System)
    {
    }

    internal CredentialCommands(
        string appName,
        IEnumerable<CredentialDefinition> credentials,
        IConsoleIO console,
        Func<string?, SecretStore>? storeFactory,
        TimeProvider timeProvider)
    {
        _ = SecretStore.GetDefaultPath(appName); // Validates the app name.
        ArgumentNullException.ThrowIfNull(credentials);

        var list = credentials.ToList();
        if (list.Count == 0)
        {
            throw new ArgumentException("At least one credential is required.", nameof(credentials));
        }

        if (list.Contains(null!))
        {
            throw new ArgumentException("Credentials can't contain null.", nameof(credentials));
        }

        var duplicate = list.GroupBy(c => c.Name, StringComparer.Ordinal).FirstOrDefault(g => g.Count() > 1);
        if (duplicate is not null)
        {
            throw new ArgumentException($"The credential '{duplicate.Key}' is defined more than once.", nameof(credentials));
        }

        AppName = appName;
        Credentials = list;
        _console = console;
        _storeFactory = storeFactory ?? (path => new SecretStore(appName, path));
        _timeProvider = timeProvider;
    }

    /// <summary>The app name passed to <see cref="SecretStore"/>.</summary>
    public string AppName { get; }

    /// <summary>The credentials the app needs, in prompt order.</summary>
    public IReadOnlyList<CredentialDefinition> Credentials { get; }

    /// <summary>
    /// The secrets file path to use when <c>--secrets-path</c> isn't given, for example from the app's config.
    /// When <see langword="null"/>, <see cref="SecretStore.GetDefaultPath"/> is used.
    /// </summary>
    public string? SecretsPath { get; init; }

    /// <summary>An optional check against the real service, run after every secret decrypts.</summary>
    public CredentialCheck? ServiceCheck { get; init; }

    /// <summary>What <see cref="ServiceCheck"/> talks to, for messages such as "Checking with the Jira server...".</summary>
    public string ServiceName { get; init; } = "the service";

    /// <summary>Whether <paramref name="command"/> is one of the credential commands.</summary>
    public static bool IsCredentialCommand(string? command) =>
        command is SetCommand or VerifyCommand or InfoCommand or DescribeCommand;

    /// <summary>
    /// Finds the value of <c>--secrets-path</c> in <paramref name="args"/>, or returns <see langword="null"/> if it isn't there.
    /// Other arguments are ignored, so the app can use this alongside its own options.
    /// </summary>
    /// <exception cref="ArgumentException">The option is given without a value.</exception>
    public static string? FindSecretsPath(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        string? path = null;
        for (var i = 0; i < args.Count; i++)
        {
            if (args[i] == SecretsPathOption)
            {
                if (i + 1 >= args.Count || string.IsNullOrWhiteSpace(args[i + 1]) || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    throw new ArgumentException($"{SecretsPathOption} needs a path.", nameof(args));
                }

                path = args[++i];
            }
            else if (args[i].StartsWith(SecretsPathOption + "=", StringComparison.Ordinal))
            {
                path = args[i][(SecretsPathOption.Length + 1)..];
                if (string.IsNullOrWhiteSpace(path))
                {
                    throw new ArgumentException($"{SecretsPathOption} needs a path.", nameof(args));
                }
            }
        }

        return path;
    }

    /// <summary>
    /// Creates the store the app should read its secrets from: <c>--secrets-path</c> from <paramref name="args"/>
    /// if given, otherwise <see cref="SecretsPath"/>, otherwise the default path.
    /// </summary>
    /// <exception cref="ArgumentException"><c>--secrets-path</c> is given without a value.</exception>
    public SecretStore CreateStore(IReadOnlyList<string> args) => _storeFactory(FindSecretsPath(args) ?? SecretsPath);

    /// <summary>
    /// Runs a credential command if <paramref name="args"/> starts with one.
    /// </summary>
    /// <returns>The exit code, or <see langword="null"/> if the arguments aren't a credential command and the app should carry on.</returns>
    public async Task<int?> TryRunAsync(IReadOnlyList<string> args, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Count == 0 || !IsCredentialCommand(args[0]))
        {
            return null;
        }

        var command = args[0];
        var options = args.Skip(1).ToList();
        if (options.Any(o => o is "--help" or "-h" or "-?" or "/?"))
        {
            WriteUsage(_console.Out);
            return ExitSuccess;
        }

        SecretStore store;
        try
        {
            if (options.Where((o, i) => !IsSecretsPathPart(options, i)).Any())
            {
                // Never echo the argument: it may be a secret someone tried to pass on the command line.
                _console.Error.WriteLine(
                    $"{command} only accepts {SecretsPathOption} <path>. Secrets are never accepted on the command line; you'll be prompted for them.");
                return ExitUsage;
            }

            store = CreateStore(options);
        }
        catch (ArgumentException ex)
        {
            _console.Error.WriteLine(ex.Message);
            return ExitUsage;
        }

        return command switch
        {
            SetCommand => await SetAsync(store, cancellationToken).ConfigureAwait(false),
            VerifyCommand => await VerifyAsync(store, writeHeader: true, cancellationToken).ConfigureAwait(false),
            DescribeCommand => Describe(store),
            _ => ShowInfo(store),
        };
    }

    /// <summary>Writes help for the credential commands, for inclusion in the app's own help.</summary>
    public void WriteUsage(TextWriter writer)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteLine("Credential commands:");
        writer.WriteLine($"  {SetCommand,-23} Prompt for credentials, encrypt them for the current Windows account, and save them.");
        writer.WriteLine($"  {VerifyCommand,-23} Check that the saved credentials decrypt and work, without showing them.");
        writer.WriteLine($"  {InfoCommand,-23} Show where the credentials are stored, who encrypted them and when.");
        writer.WriteLine($"  {DescribeCommand,-23} Print the credential definitions as JSON, for the Lockbox setup tool.");
        writer.WriteLine();
        writer.WriteLine("Options:");
        writer.WriteLine($"  {SecretsPathOption + " <path>",-23} Use this secrets file instead of {SecretsPath ?? $@"%APPDATA%\{AppName}\{SecretStore.DefaultFileName}"}.");
        writer.WriteLine();
        writer.WriteLine("Run these as the Windows account that will run the app. Only that account can decrypt the credentials.");
    }

    private static bool IsSecretsPathPart(List<string> options, int index) =>
        options[index] == SecretsPathOption
        || options[index].StartsWith(SecretsPathOption + "=", StringComparison.Ordinal)
        || (index > 0 && options[index - 1] == SecretsPathOption);

    private async Task<int> SetAsync(SecretStore store, CancellationToken cancellationToken)
    {
        var output = _console.Out;
        var current = store.CurrentAccount;
        output.WriteLine($"Secrets file:  {store.FilePath}");
        output.WriteLine($"Encrypting as: {current}");
        output.WriteLine("Only this Windows account can decrypt these credentials. If the app runs as a different account");
        output.WriteLine($"(for example a scheduled task), run {SetCommand} as that account instead.");

        if (!TryPrepareFile(store, out var replaceFile, out var keepable))
        {
            return ExitFailure;
        }

        output.WriteLine();
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var credential in Credentials)
        {
            var canKeep = keepable.Contains(credential.Name);
            var prompt = canKeep ? $"{credential.Prompt} (Enter to keep the current value): " : $"{credential.Prompt}: ";
            while (true)
            {
                output.Write(prompt);
                var input = credential.Masked ? _console.ReadMasked() : _console.ReadLine()?.Trim();
                if (input is null)
                {
                    output.WriteLine();
                    _console.Error.WriteLine("Cancelled. Nothing was saved.");
                    return ExitFailure;
                }

                // Whitespace-only counts as blank, even for masked values (which are otherwise kept exactly as typed).
                if (!string.IsNullOrWhiteSpace(input))
                {
                    values[credential.Name] = input;
                    break;
                }

                if (canKeep)
                {
                    break;
                }

                output.WriteLine("A value is required. Press Escape to cancel.");
            }
        }

        if (values.Count == 0)
        {
            output.WriteLine("Nothing changed.");
        }
        else
        {
            try
            {
                if (replaceFile)
                {
                    store.ReplaceSecrets(values);
                }
                else
                {
                    store.SetSecrets(values);
                }
            }
            catch (SecretStoreException ex)
            {
                _console.Error.WriteLine(ex.Message);
                return ExitFailure;
            }

            output.WriteLine(values.Count == 1 ? "Saved 1 credential." : $"Saved {values.Count} credentials.");
        }

        output.WriteLine();
        return await VerifyAsync(store, writeHeader: false, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Checks the existing file before prompting. Decides whether it must be replaced (another account's,
    /// another protector's, or corrupt) and which current values can be kept.
    /// </summary>
    private bool TryPrepareFile(SecretStore store, out bool replaceFile, out HashSet<string> keepable)
    {
        replaceFile = false;
        keepable = new HashSet<string>(StringComparer.Ordinal);
        var status = store.Inspect(Credentials.Select(c => c.Name));

        switch (status.FileState)
        {
            case SecretFileState.Missing:
            case SecretFileState.Usable:
                keepable.UnionWith(status.Secrets.Where(s => s.State == SecretState.Usable).Select(s => s.Name));
                return true;

            case SecretFileState.Corrupt:
                _console.Out.WriteLine();
                _console.Out.WriteLine(status.Error!.Message);
                replaceFile = Confirm("Replace the file and enter all credentials again?");
                return replaceFile;

            case SecretFileState.OtherAccount:
            case SecretFileState.OtherProtector:
                var info = status.Info!;
                _console.Out.WriteLine();
                _console.Out.WriteLine(status.FileState == SecretFileState.OtherAccount
                    ? $"This file's credentials were encrypted by {info.EncryptedBy}. You're running as {store.CurrentAccount}, so you can't add to them."
                    : $"This file's credentials were encrypted with '{info.Protector}', not '{store.ProtectorId}', so you can't add to them.");
                replaceFile = Confirm($"Replace all {info.Secrets.Count} credential(s) in this file with new ones?");
                return replaceFile;

            default:
                _console.Error.WriteLine(status.Error!.Message);
                return false;
        }
    }

    private bool Confirm(string question)
    {
        _console.Out.Write($"{question} [y/N] ");
        var answer = _console.ReadLine()?.Trim();
        var confirmed = answer is not null && (answer.Equals("y", StringComparison.OrdinalIgnoreCase) || answer.Equals("yes", StringComparison.OrdinalIgnoreCase));
        if (!confirmed)
        {
            _console.Error.WriteLine("Nothing was changed.");
        }

        return confirmed;
    }

    private async Task<int> VerifyAsync(SecretStore store, bool writeHeader, CancellationToken cancellationToken)
    {
        var output = _console.Out;
        if (writeHeader)
        {
            output.WriteLine($"Secrets file:  {store.FilePath}");
            output.WriteLine($"Running as:    {store.CurrentAccount}");
            output.WriteLine();
        }

        IReadOnlyList<SecretCheckResult> results;
        try
        {
            results = store.CheckSecrets(Credentials.Select(c => c.Name));
        }
        catch (SecretStoreException ex)
        {
            _console.Error.WriteLine(ex.Message);
            return ExitFailure;
        }

        var width = Credentials.Max(c => c.Name.Length);
        foreach (var result in results)
        {
            output.WriteLine($"  {result.Name.PadRight(width)}  {(result.Succeeded ? "OK" : "FAILED")}");
            if (result.Error is { } error)
            {
                output.WriteLine($"    {error.Message}");
            }
        }

        if (results.Any(r => !r.Succeeded))
        {
            return ExitFailure;
        }

        if (ServiceCheck is null)
        {
            return ExitSuccess;
        }

        output.Write($"Checking with {ServiceName}... ");
        CredentialCheckResult check;
        try
        {
            var values = Credentials.ToDictionary(c => c.Name, c => store.GetSecret(c.Name), StringComparer.Ordinal);
            check = await ServiceCheck(values, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
#pragma warning disable CA1031 // The check is app code; any failure is reported rather than crashing the command.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            output.WriteLine("FAILED");
            output.WriteLine($"  {ex.GetType().Name}: {ex.Message}");
            return ExitFailure;
        }

        output.WriteLine(check.Succeeded ? "OK" : "FAILED");
        if (!string.IsNullOrWhiteSpace(check.Message))
        {
            output.WriteLine($"  {check.Message}");
        }

        return check.Succeeded ? ExitSuccess : ExitFailure;
    }

    private int Describe(SecretStore store)
    {
        var buffer = new ArrayBufferWriter<byte>();

        // The default encoder escapes non-ASCII characters, so the output survives any console code page.
        using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartObject();
            json.WriteString("format", DescribeFormat);
            json.WriteString("appName", AppName);
            json.WriteString("secretsPath", store.FilePath);
            json.WriteString("serviceName", ServiceName);
            json.WriteBoolean("hasServiceCheck", ServiceCheck is not null);
            json.WriteStartArray("credentials");
            foreach (var credential in Credentials)
            {
                json.WriteStartObject();
                json.WriteString("name", credential.Name);
                json.WriteString("prompt", credential.Prompt);
                json.WriteBoolean("masked", credential.Masked);
                json.WriteEndObject();
            }

            json.WriteEndArray();
            json.WriteEndObject();
        }

        _console.Out.WriteLine(Encoding.UTF8.GetString(buffer.WrittenSpan));
        return ExitSuccess;
    }

    private int ShowInfo(SecretStore store)
    {
        var output = _console.Out;
        var current = store.CurrentAccount;
        output.WriteLine($"Secrets file:  {store.FilePath}");

        SecretFileInfo info;
        try
        {
            info = store.GetInfo();
        }
        catch (SecretStoreException ex) when (ex.Error == SecretStoreError.FileNotFound)
        {
            output.WriteLine("               (doesn't exist yet)");
            output.WriteLine($"Running as:    {current}");
            output.WriteLine();
            output.WriteLine($"Run {SetCommand} as the account that will run the app to create it.");
            return ExitFailure;
        }
        catch (SecretStoreException ex)
        {
            _console.Error.WriteLine(ex.Message);
            return ExitFailure;
        }

        output.WriteLine($"Protector:     {info.Protector}");
        output.WriteLine($"Encrypted by:  {(info.EncryptedBy is { } by ? $"{by}{(by.Sid is null ? "" : $" ({by.Sid})")}" : "(not recorded)")}");
        output.WriteLine($"Running as:    {current}");
        if (info.EncryptedBy is { } owner && info.Secrets.Count > 0)
        {
            if (!owner.IsSameAccountAs(current))
            {
                output.WriteLine($"               This account can't decrypt these credentials. Run the app as {owner.Account},");
                output.WriteLine($"               or run {SetCommand} to replace them with your own.");
            }
            else if (!owner.IsSameMachineAs(current))
            {
                output.WriteLine($"               Encrypted on {owner.Machine}. They only decrypt here with a roaming profile.");
            }
        }

        output.WriteLine();
        output.WriteLine("Credentials:");
        var created = info.Secrets.ToDictionary(s => s.Name, s => s.CreatedUtc, StringComparer.Ordinal);
        var extra = info.Secrets.Select(s => s.Name).Where(n => !Credentials.Any(c => c.Name == n)).ToList();
        var width = Credentials.Select(c => c.Name).Concat(extra).Max(n => n.Length);
        var now = _timeProvider.GetUtcNow().UtcDateTime;

        foreach (var credential in Credentials)
        {
            output.WriteLine(created.TryGetValue(credential.Name, out var when)
                ? $"  {credential.Name.PadRight(width)}  set {Describe(when, now)}"
                : $"  {credential.Name.PadRight(width)}  missing");
        }

        foreach (var name in extra)
        {
            output.WriteLine($"  {name.PadRight(width)}  set {Describe(created[name], now)}, not used by this app");
        }

        return ExitSuccess;
    }

    private static string Describe(DateTime createdUtc, DateTime nowUtc)
    {
        var age = nowUtc - createdUtc;
        var ago = age.TotalMinutes < 1 ? "just now"
            : age.TotalHours < 1 ? Plural((int)age.TotalMinutes, "minute") + " ago"
            : age.TotalDays < 1 ? Plural((int)age.TotalHours, "hour") + " ago"
            : Plural((int)age.TotalDays, "day") + " ago";
        return $"{createdUtc.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)} UTC ({ago})";
    }

    private static string Plural(int count, string unit) => count == 1 ? $"1 {unit}" : $"{count} {unit}s";
}
