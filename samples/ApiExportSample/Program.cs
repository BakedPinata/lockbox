// ApiExportSample: an export app that signs in to an API with a username and password, receives a short-lived
// JWT, and sends it as "Authorization: Bearer <jwt>". The username and password are stored with Lockbox.
//
//   ApiExportSample set-credentials        (run as the Windows account that will run the export)
//   ApiExportSample verify-credentials
//   ApiExportSample show-credentials-info
//   ApiExportSample export [--out records.json] [--delay-ms 500] [--verbose] [--secrets-path <path>]

using System.Text.Json;
using ApiExportSample;
using ApiExportSample.Auth;
using Lockbox;
using Lockbox.Cli;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SampleSupport;

const string AppName = "ApiExportSample";
const string UsernameSecret = "api.username";
const string PasswordSecret = "api.password";

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

// 1. The credential commands. verify-credentials also signs in to prove the password works.
var credentialCommands = new CredentialCommands(AppName,
[
    new CredentialDefinition(UsernameSecret, "Username", masked: false),
    new CredentialDefinition(PasswordSecret, "Password"),
])
{
    SecretsPath = settings.SecretsPath,
    ServiceName = settings.BaseUrl ?? "the API",
    ServiceCheck = async (values, ct) =>
    {
        try
        {
            var baseUrl = ServiceUrl.Parse(settings.BaseUrl);
            await using var services = ApiServices.Build(baseUrl, new ApiCredentials(values[UsernameSecret], values[PasswordSecret]), verbose: false, l => l.ClearProviders());
            var token = await services.GetRequiredService<LoginClient>().LoginAsync(ct);
            return CredentialCheckResult.Success(token.ExpiresAt is { } expires
                ? $"Signed in. The token is valid until {expires:HH:mm:ss} UTC."
                : "Signed in.");
        }
        catch (Exception ex) when (ex is LoginFailedException or ArgumentException)
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
    Console.WriteLine("  export                  Export all records from the API.");
    Console.WriteLine();
    credentialCommands.WriteUsage(Console.Out);
    Console.WriteLine();
    Console.WriteLine(ExportOptions.UsageText("records.json"));
    return args is [] or ["--help" or "-h" or "help"] ? CredentialCommands.ExitSuccess : CredentialCommands.ExitUsage;
}

// 2. Parse the export's options and settings.
ExportOptions options;
Uri apiUrl;
SecretStore store;
try
{
    options = ExportOptions.Parse(args[1..], "records.json");
    apiUrl = ServiceUrl.Parse(settings.BaseUrl);
    store = credentialCommands.CreateStore(args);
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine(ex.Message);
    return CredentialCommands.ExitUsage;
}

// 3. Decrypt the credentials. They stay in memory for this run only.
ApiCredentials credentials;
try
{
    credentials = new ApiCredentials(store.GetSecret(UsernameSecret), store.GetSecret(PasswordSecret));
}
catch (SecretStoreException ex)
{
    Console.Error.WriteLine(ex.Message);
    return CredentialCommands.ExitFailure;
}

// 4. Export. Signing in, renewing the JWT before it expires, and retrying once on a 401 all happen in
//    BearerTokenHandler / TokenProvider, so the export code never handles a token.
await using var serviceProvider = ApiServices.Build(apiUrl, credentials, options.Verbose);
try
{
    var records = await serviceProvider.GetRequiredService<RecordExporter>().ExportAsync(options.Delay, cancellation.Token);
    await File.WriteAllTextAsync(options.OutputPath, JsonSerializer.Serialize(records, SampleJson.Indented), cancellation.Token);
    Console.WriteLine($"Exported {records.Count} records to {options.OutputPath}");
    return CredentialCommands.ExitSuccess;
}
catch (Exception ex) when (ex is LoginFailedException or ApiAuthorizationException)
{
    Console.Error.WriteLine(ex.Message);
    return CredentialCommands.ExitFailure;
}
catch (HttpRequestException ex)
{
    Console.Error.WriteLine($"The export failed talking to {apiUrl}: {ex.Message}");
    return CredentialCommands.ExitFailure;
}
catch (OperationCanceledException) when (cancellation.Token.IsCancellationRequested)
{
    Console.Error.WriteLine("Cancelled.");
    return CredentialCommands.ExitFailure;
}
