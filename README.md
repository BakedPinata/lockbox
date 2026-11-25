# Lockbox

Lockbox keeps the credentials of .NET console apps (passwords, API tokens, personal access tokens) out of plain
text. Each app's secrets are encrypted with **Windows DPAPI** for the Windows account that runs the app, and stored
in a small JSON file. The file can sit anywhere, even on a file share other people can read: to them it's an
unusable blob.

- **Lockbox:** the library. Load and save named secrets, with error messages that say how to fix the problem.
- **Lockbox.Cli:** adds `set-credentials`, `verify-credentials` and `show-credentials-info` to any console app.
- **LockboxSetup.exe:** a Windows app for entering any Lockbox app's credentials.
- **samples/:** two demonstration apps (a Jira PAT, and a username/password → JWT API) and a mock server.

Contents: [How it works](#how-it-works) · [Using an app that uses Lockbox](#using-an-app-that-uses-lockbox) ·
[Running on a server](#running-on-a-server-scheduled-tasks) · [Troubleshooting](#troubleshooting) ·
[Adding Lockbox to an app](#adding-lockbox-to-an-app) · [Building and testing](#building-and-testing)

## How it works

Lockbox uses `System.Security.Cryptography.ProtectedData` with `DataProtectionScope.CurrentUser`. Windows derives
the key from the account's credentials, so there is no key for the app to store.

- **Only the account that saved a secret can decrypt it**, normally only on the machine where it was saved (a
  roaming domain profile can carry it to other machines). Every other user, including other people who run the
  same app, gets an error.
- Each value is also bound to the app name and the secret's name, so values can't be swapped between entries or
  read by another app running as the same user.
- The file records who encrypted it. That's only used to explain failures, for example *"This file was encrypted
  by DOMAIN\x on PC123; you are running as DOMAIN\y on SRV01"*.
- One file holds one account's secrets. Saving as another account offers to replace the file; it never mixes them.

```json
{
  "version": 1,
  "protector": "dpapi-user",
  "encryptedBy": { "account": "DOMAIN\\user", "sid": "S-1-5-21-…", "machine": "PC123" },
  "secrets": {
    "jira.pat": { "createdUtc": "2026-11-24T14:51:00Z", "ciphertext": "AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAA…" }
  }
}
```

**What it protects against:** other users who can read the file, on the same machine or on a share. **What it
doesn't:** anyone who can run code as the same account, and administrators of the machine. Treat the account that
runs an unattended job accordingly.

## Using an app that uses Lockbox

Credentials are entered once per Windows account, at a prompt or in the setup tool. They're never passed on the
command line, because command lines end up in shell history and process listings.

**At the console** (`JiraExport.exe` stands for your app):

```text
> JiraExport.exe set-credentials
Secrets file:  C:\Users\alice\AppData\Roaming\JiraExport\secrets.json
Encrypting as: CONTOSO\alice on PC01
Only this Windows account can decrypt these credentials. …

Jira personal access token: ********
Saved 1 credential.

  jira.pat  OK
Checking with https://jira.example.com/... OK
  Signed in as Alice Example.
```

| Command | What it does |
|---|---|
| `set-credentials` | Prompts for each credential (masked), encrypts and saves them, then verifies them. Press Enter to keep a current value. Escape cancels. |
| `verify-credentials` | Checks that each credential decrypts and, if the app supports it, that the service accepts it. Never shows values. |
| `show-credentials-info` | Shows the file's path, who encrypted it, and when each credential was set. No values. |
| `--secrets-path <path>` | Use a different secrets file, for example a home folder on a file share. |

The default file is `%APPDATA%\<AppName>\secrets.json`. An app may also set a different path in its settings.

**With the setup tool:** run `LockboxSetup.exe --app C:\Apps\JiraExport.exe` (or start it and choose the app).
It asks the app which credentials it needs, shows a field for each with its current state, and saves them
encrypted for the account running the tool. **Save** also runs the app's own `verify-credentials`. It works with
any app built with Lockbox.Cli 0.2 or later.

## Running on a server (scheduled tasks)

An unattended job decrypts its credentials as the account it runs as, so **the credentials must be saved as that
same account, on that machine**:

1. Create the job's Windows account. A domain account is best (see below).
2. On the server, save the credentials as that account. Either log on as it, or use `runas`:

   ```text
   runas /user:SERVER\jobaccount "C:\Apps\JiraExport.exe set-credentials"
   runas /user:SERVER\jobaccount "\"C:\Tools\LockboxSetup.exe\" --app \"C:\Apps\JiraExport.exe\""
   ```

   The setup tool's **Run as another account** box builds the second command for you.
3. Run `verify-credentials` the same way.
4. Create the task in Task Scheduler: **Run whether user is logged on or not**, as the job account. Leave **Do not
   store password** unticked: without the stored password, Windows may not be able to unlock the account's DPAPI
   keys, and decryption fails. The account needs the "Log on as a batch job" right (Task Scheduler normally grants
   it when you save the task, unless group policy prevents it).

**Things that break it, and the fix (re-run `set-credentials` as the job account):**

- **The service password changes or the PAT expires.** Note the PAT's expiry date. `verify-credentials` reports
  the service's rejection.
- **An administrator resets a local account's password.** The account's DPAPI keys are lost, so its secrets
  can't be decrypted. (Changing the password normally, or any reset of a domain account, is fine: the domain
  keeps a backup key.)
- **The job moves to another server or profile.** Encrypted values don't move with it.

`samples/e2e.ps1` runs the whole flow against the mock server, so it makes a good first dry run on a new server.

## Troubleshooting

Every error says what went wrong and what to do. The common ones:

| Message starts with | Why | Fix |
|---|---|---|
| *No secrets file was found* | Nothing has been saved for this app and path yet. | Run `set-credentials` as the account that runs the app. |
| *…can't be decrypted. This file was encrypted by X on A; you are running as Y on B* | Another account saved these credentials. | Run the app as X, or run `set-credentials` as Y (it offers to replace the file). |
| *…This file was encrypted on A; you are running on B* | Same account, different machine, no roaming profile. | Run `set-credentials` on this machine. |
| *…It was encrypted by this account* | The entry was copied or edited, or an administrator reset this (local) account's password. | Run `set-credentials` again. |
| *…is damaged or isn't a Lockbox secrets file* | The JSON was edited or truncated. | Run `set-credentials` (it offers to replace the file). |
| *…has format version N* | A newer version of the app wrote the file. | Update the app. Don't delete the file unless you mean to re-enter everything. |
| *The API rejected the username or password* / *Jira rejected the personal access token* | The credentials decrypted, but the service refused them. | Get the new password or a new PAT, then run `set-credentials`. |

`show-credentials-info` shows who encrypted the file, which account you're running as, and the age of each credential.

## Adding Lockbox to an app

### 1. Reference the packages

Apps usually live in their own solutions, so consume Lockbox as NuGet packages. Until there's a shared feed, pack
them into a folder:

```bash
dotnet pack Lockbox -c Release -o C:\nuget-local
dotnet pack Lockbox.Cli -c Release -o C:\nuget-local
```

Then add that folder as a package source, in a `nuget.config` next to the app's solution:

```xml
<configuration>
  <packageSources>
    <add key="lockbox-local" value="C:\nuget-local" />
  </packageSources>
</configuration>
```

Then run `dotnet add package Lockbox.Cli`, which brings in `Lockbox` too. The app must target `net9.0-windows` or
`net10.0-windows`: the packages contain a build for each.

### 2. Wire up the commands and read the secrets

```csharp
using Lockbox;
using Lockbox.Cli;

var credentials = new CredentialCommands("JiraExport",   // Keep this name stable: secrets are bound to it.
    [new CredentialDefinition("jira.pat", "Jira personal access token")])
{
    SecretsPath = settings.SecretsPath,                   // Optional override from config; null = %APPDATA%.
    ServiceName = settings.JiraUrl,
    ServiceCheck = async (values, ct) =>                  // Optional: lets verify-credentials test with the service.
    {
        var user = await GetMyselfAsync(values["jira.pat"], ct);
        return CredentialCheckResult.Success($"Signed in as {user.DisplayName}.");
    },
};

// set-credentials, verify-credentials, show-credentials-info and describe-credentials.
if (await credentials.TryRunAsync(args) is int exitCode)
{
    return exitCode;
}

string pat;
try
{
    pat = credentials.CreateStore(args).GetSecret("jira.pat");   // Honours --secrets-path.
}
catch (SecretStoreException ex)
{
    Console.Error.WriteLine(ex.Message);                      // Already says how to fix it.
    return 1;
}
```

Add `credentials.WriteUsage(Console.Out)` to the app's help text.

### 3. Use the secrets safely

- Keep secret values (and any tokens obtained with them) **in memory only**. Never write them to disk or config.
- **Never log them.** Call `.RedactLoggedHeaders(_ => true)` on every `IHttpClientFactory` client, so the
  `Authorization` header is logged as `*`. Don't put secrets in exception messages, and don't use records for
  types that hold them (their generated `ToString` prints every property).
- Send credentials over `https://` only.

The samples show the two common cases in full. [samples/README.md](samples/README.md) lists what to copy:

- **A token that doesn't expire during a run** (a Jira PAT): set it as the client's default
  `Authorization: Bearer` header. See `samples/JiraExportSample`.
- **A username and password exchanged for a short-lived JWT:** `samples/ApiExportSample/Auth/` has a
  `DelegatingHandler` that signs in, renews the token shortly before it expires, and on a 401 signs in again once
  and retries once. Adapt `LoginClient` to the real login endpoint.

### 4. Publish

Publish self-contained so that the target machine needs no .NET runtime. The samples' `win-x64` publish profiles
show the settings:

```bash
dotnet publish -p:PublishProfile=win-x64
```

## Building and testing

Needs the .NET 10 SDK, plus the .NET 9 runtime to run the libraries' tests on .NET 9. Everything builds on any OS;
DPAPI, the samples and the setup tool *run* only on Windows.

```bash
dotnet build
dotnet test                 # On Linux/macOS, DPAPI and WinForms tests are skipped.
pwsh samples/e2e.ps1        # Windows: publish the samples and run them end to end with real DPAPI.
```

| Project | |
|---|---|
| `Lockbox` | The library: `SecretStore`, `ISecretProtector`, `DpapiUserProtector`. Targets .NET 9 and .NET 10. |
| `Lockbox.Cli` | The credential commands for console apps. Targets .NET 9 and .NET 10. |
| `Lockbox.Setup` | The setup tool's logic, with no UI code. |
| `Lockbox.Setup.WinForms` | `LockboxSetup.exe`. |
| `Lockbox.Tests`, `Lockbox.Setup.WinForms.Tests` | Unit tests. `Lockbox.Tests` runs on .NET 9 and .NET 10; the WinForms tests run on Windows only. |
| `samples/` | Demonstration apps, mock server, sample tests, `e2e.ps1`. |

CI (GitHub Actions) builds and tests on Windows and Linux, and runs `samples/e2e.ps1` on Windows.

[PLAN.md](PLAN.md) records the design decisions, the alternatives that were rejected, and why.
