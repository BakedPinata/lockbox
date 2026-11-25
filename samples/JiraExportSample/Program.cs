// JiraExportSample: an export app that authenticates to Jira Server/Data Center with a personal access token
// (PAT), sent as "Authorization: Bearer <pat>". The PAT is stored with Lockbox.
//
//   JiraExportSample set-credentials        (run as the Windows account that will run the export)
//   JiraExportSample verify-credentials
//   JiraExportSample show-credentials-info
//   JiraExportSample export [--jql "project = DEMO"] [--out issues.json] [--delay-ms 500] [--verbose] [--secrets-path <path>]

using System.Text.Json;
using JiraExportSample;
using Lockbox;
using Lockbox.Cli;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SampleSupport;

const string AppName = "JiraExportSample";
const string PatSecret = "jira.pat";

SampleSettings settings;
try
{
    settings = SampleSettings.Load($"{AppName}.settings.json");
}
catch (InvalidDataException ex)
{
    Console.Error.WriteLine(ex.Message);
    return CredentialCommands.ExitFailure;
}

using var cancellation = new ConsoleCancellation();

// 1. The credential commands. verify-credentials also calls /myself to prove the PAT works.
var credentialCommands = new CredentialCommands(AppName, [new CredentialDefinition(PatSecret, "Jira personal access token")])
{
    SecretsPath = settings.SecretsPath,
    ServiceName = settings.BaseUrl ?? "Jira",
    ServiceCheck = async (values, ct) =>
    {
        try
        {
            var baseUrl = ServiceUrl.Parse(settings.BaseUrl);
            await using var services = JiraServices.Build(baseUrl, values[PatSecret], verbose: false, l => l.ClearProviders());
            var user = await services.GetRequiredService<JiraClient>().GetMyselfAsync(ct);
            return CredentialCheckResult.Success($"Signed in as {user.DisplayName ?? user.Name}.");
        }
        catch (Exception ex) when (ex is JiraAuthorizationException or ArgumentException)
        {
            return CredentialCheckResult.Failure(ex.Message);
        }
    },
};

if (await credentialCommands.TryRunAsync(args, cancellation.Token) is int exitCode)
{
    return exitCode;
}

if (args is not ["export", ..])
{
    Console.WriteLine($"Usage: {AppName} <command> [options]");
    Console.WriteLine();
    Console.WriteLine("  export                  Export the issues matching --jql (default: all issues).");
    Console.WriteLine("    --jql <query>         The JQL query (default: \"order by key\").");
    Console.WriteLine();
    credentialCommands.WriteUsage(Console.Out);
    Console.WriteLine();
    Console.WriteLine(ExportOptions.UsageText("issues.json"));
    return args is [] or ["--help" or "-h" or "help"] ? CredentialCommands.ExitSuccess : CredentialCommands.ExitUsage;
}

// 2. Parse the export's options and settings.
ExportOptions options;
Uri jiraUrl;
SecretStore store;
try
{
    options = ExportOptions.Parse(args[1..], "issues.json", "--jql");
    jiraUrl = ServiceUrl.Parse(settings.BaseUrl);
    store = credentialCommands.CreateStore(args);
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine(ex.Message);
    return CredentialCommands.ExitUsage;
}

// 3. Decrypt the PAT. It stays in memory for this run only.
string pat;
try
{
    pat = store.GetSecret(PatSecret);
}
catch (SecretStoreException ex)
{
    Console.Error.WriteLine(ex.Message);
    return CredentialCommands.ExitFailure;
}

// 4. Export.
await using var serviceProvider = JiraServices.Build(jiraUrl, pat, options.Verbose);
try
{
    var jql = options.Extra.GetValueOrDefault("--jql", "order by key");
    var issues = await serviceProvider.GetRequiredService<JiraClient>().SearchAsync(jql, options.Delay, cancellation.Token);
    await File.WriteAllTextAsync(options.OutputPath, JsonSerializer.Serialize(issues, SampleJson.Indented), cancellation.Token);
    Console.WriteLine($"Exported {issues.Count} issues to {options.OutputPath}");
    return CredentialCommands.ExitSuccess;
}
catch (JiraAuthorizationException ex)
{
    Console.Error.WriteLine(ex.Message);
    return CredentialCommands.ExitFailure;
}
catch (HttpRequestException ex)
{
    Console.Error.WriteLine($"The export failed talking to {jiraUrl}: {ex.Message}");
    return CredentialCommands.ExitFailure;
}
catch (OperationCanceledException) when (cancellation.Token.IsCancellationRequested)
{
    Console.Error.WriteLine("Cancelled.");
    return CredentialCommands.ExitFailure;
}
