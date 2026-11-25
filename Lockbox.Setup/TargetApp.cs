using System.ComponentModel;
using System.Diagnostics;
using System.Text;

namespace Lockbox.Setup;

/// <summary>The exit code and combined output of a process.</summary>
public sealed record ProcessResult(int ExitCode, string Output);

/// <summary>Runs a process. Replaced in tests.</summary>
public interface IProcessRunner
{
    /// <exception cref="InvalidOperationException">The process couldn't be started or timed out.</exception>
    Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>Runs processes without a window, capturing stdout and stderr. Nothing is written to stdin.</summary>
public sealed class ProcessRunner : IProcessRunner
{
    /// <inheritdoc />
    public async Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var start = new ProcessStartInfo(fileName)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = start };
        var output = new StringBuilder();
        var sync = new Lock();
        void Append(object sender, DataReceivedEventArgs e)
        {
            if (e.Data is not null)
            {
                lock (sync)
                {
                    output.AppendLine(e.Data);
                }
            }
        }

        process.OutputDataReceived += Append;
        process.ErrorDataReceived += Append;
        try
        {
            process.Start();
        }
        catch (Win32Exception ex)
        {
            throw new InvalidOperationException($"'{fileName}' couldn't be started: {ex.Message}", ex);
        }

        // An empty, closed stdin: a command that unexpectedly prompts sees end of input instead of hanging.
        process.StandardInput.Close();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        try
        {
            await process.WaitForExitAsync(timeoutSource.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            cancellationToken.ThrowIfCancellationRequested();
            throw new InvalidOperationException($"'{Path.GetFileName(fileName)}' didn't finish within {timeout.TotalSeconds:0} seconds.");
        }

        lock (sync)
        {
            return new ProcessResult(process.ExitCode, output.ToString());
        }
    }
}

/// <summary>
/// The console app whose credentials are being set up. It's asked to describe its credentials and to verify them,
/// so this tool works with any app that uses Lockbox.Cli, without knowing about it in advance.
/// </summary>
public sealed class TargetApp
{
    private static readonly TimeSpan DescribeTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan VerifyTimeout = TimeSpan.FromMinutes(2);
    private readonly IProcessRunner _runner;

    /// <param name="path">The app's <c>.exe</c>, or a framework-dependent <c>.dll</c> (run with <c>dotnet</c>).</param>
    /// <param name="runner">Runs the app. Defaults to <see cref="ProcessRunner"/>.</param>
    public TargetApp(string path, IProcessRunner? runner = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        Path = System.IO.Path.GetFullPath(path);
        _runner = runner ?? new ProcessRunner();
    }

    /// <summary>The app's full path.</summary>
    public string Path { get; }

    /// <summary>Runs <c>describe-credentials</c>.</summary>
    /// <exception cref="InvalidOperationException">The app couldn't be run or doesn't support the command.</exception>
    public async Task<AppDescription> DescribeAsync(string? secretsPath, CancellationToken cancellationToken)
    {
        var result = await RunAsync("describe-credentials", secretsPath, DescribeTimeout, cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"{System.IO.Path.GetFileName(Path)} couldn't describe its credentials (exit code {result.ExitCode}). " +
                "It needs to use Lockbox.Cli 0.2 or later." + Environment.NewLine + result.Output.Trim());
        }

        try
        {
            return AppDescription.Parse(result.Output);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException($"{System.IO.Path.GetFileName(Path)}: {ex.Message}", ex);
        }
    }

    /// <summary>Runs <c>verify-credentials</c>, which decrypts each secret and, if the app has one, runs its service check.</summary>
    public Task<ProcessResult> VerifyAsync(string secretsPath, CancellationToken cancellationToken) =>
        RunAsync("verify-credentials", secretsPath, VerifyTimeout, cancellationToken);

    private Task<ProcessResult> RunAsync(string command, string? secretsPath, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var arguments = new List<string>();
        var fileName = Path;
        if (Path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
        {
            fileName = "dotnet";
            arguments.Add(Path);
        }

        arguments.Add(command);
        if (!string.IsNullOrWhiteSpace(secretsPath))
        {
            arguments.Add("--secrets-path");
            arguments.Add(secretsPath);
        }

        return _runner.RunAsync(fileName, arguments, timeout, cancellationToken);
    }
}
