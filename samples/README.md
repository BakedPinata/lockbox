# Demonstration apps

Two console apps that show how a consuming app stores its credentials with Lockbox and uses them, and a mock
server so you can run them without real services.

| Project | Shows |
|---|---|
| [JiraExportSample](JiraExportSample/) | A Jira Server/Data Center **personal access token**, sent as `Authorization: Bearer <pat>`. |
| [ApiExportSample](ApiExportSample/) | A **username + password** exchanged for a short-lived **JWT**, kept in memory only, added by a `DelegatingHandler`, renewed before it expires, and on a 401 signs in again and retries once. |
| [MockServer](MockServer/) | Fake Jira and API endpoints with fake demo credentials, short-lived tokens, and optional key rotation to force 401s. Runs on any OS. |
| [SampleSupport](SampleSupport/) | Plumbing shared by the samples: settings file, HTTPS-only URLs, export options, logging. |
| [Samples.Tests](Samples.Tests/) | The samples' HTTP code against the mock (any OS). |
| [e2e.ps1](e2e.ps1) | The whole flow on Windows with real DPAPI, as CI runs it. |

The samples need Windows (DPAPI). The mock server and `Samples.Tests` run anywhere.

## Run the demo (Windows)

```powershell
# Terminal 1: the mock server. It prints the fake demo credentials.
dotnet run --project samples/MockServer

# Terminal 2: store the Jira PAT, check it, export.
dotnet run --project samples/JiraExportSample -- set-credentials        # PAT: demo-pat-0000
dotnet run --project samples/JiraExportSample -- show-credentials-info
dotnet run --project samples/JiraExportSample -- export --out issues.json

# Store the API username and password, then run a long export to watch the JWT being renewed.
dotnet run --project samples/ApiExportSample -- set-credentials         # demo / demo-password
dotnet run --project samples/ApiExportSample -- export --delay-ms 2500
```

Or enter the credentials in the setup tool instead of at the console:

```powershell
dotnet build samples/JiraExportSample
dotnet run --project Lockbox.Setup.WinForms -- --app samples/JiraExportSample/bin/Debug/net10.0-windows/JiraExportSample.exe
```

To see the 401 path, start the mock with `--invalidate-every 4`. Add `--verbose` to an export to see the HTTP
logs, with `Authorization: *` in place of the header value.

Each sample reads its non-secret settings (`BaseUrl`, and optionally `SecretsPath`) from
`<App>.settings.json` next to the executable. `BaseUrl` must be `https://`, except for localhost.

## Publish

```powershell
dotnet publish samples/ApiExportSample -p:PublishProfile=win-x64
```

The result is a single self-contained `.exe` plus its settings file in `bin\publish\win-x64\`. No .NET runtime
is needed on the target machine.

## What to copy into a real app

- **Every app:** the `Program.cs` flow. Run `CredentialCommands.TryRunAsync(args)` first, then get the secrets
  with `CreateStore(args).GetSecret(...)` and keep them in memory only. Also copy `RedactLoggedHeaders` on every
  `HttpClient`.
- **PAT apps:** `JiraServices` (a default `Authorization: Bearer` header).
- **Username/password → JWT apps:** the `Auth/` folder (`LoginClient`, `TokenProvider`, `BearerTokenHandler`,
  `AccessToken`) and `ApiServices`. Adapt `LoginClient`'s request and response to the real API.
