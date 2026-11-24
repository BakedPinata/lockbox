# Lockbox — Design & Handoff

This file captures the design decisions behind Lockbox. Read it fully before writing code. Open questions are listed at the end; resolve them before committing to the details they affect.

## Context

Lockbox is for .NET console apps that need credentials that must not be stored in plain text. Two typical apps are the reference cases, and the demonstration apps model them:

1. **API export app** (HttpClient). Uses the user's **username + password** to request a **JWT**, then sends `Authorization: Bearer <jwt>` on every later request during the export.
2. **Jira export app**. Authenticates with a **Jira Personal Access Token (PAT)**, sending `Authorization: Bearer <pat>` on every request.

Credential files may live on a shared file server that other users can read. They must not be able to recover the raw credentials.

### Deployment scenarios (both must be supported)

- **Shared tool, interactive use:** other people run the apps with *their own* credentials on their own Windows logins.
- **Server, unattended:** the apps run on a periodic trigger (Task Scheduler or a Windows service) on a Windows server, likely under a **dedicated Windows account on that server**, possibly using **one person's own credentials**.

### Hard constraint

Assume there are **no service accounts** for Jira or the other API. An unattended job may have to use a person's own password and PAT. (The *Windows* account on the server is a separate thing and is still dedicated to the job.)

## Decision: Windows DPAPI, CurrentUser scope

Use `System.Security.Cryptography.ProtectedData` (NuGet) with `DataProtectionScope.CurrentUser`.

- Ciphertext can be decrypted **only by processes running as the Windows account that encrypted it**. Windows derives and manages the key from that account's credentials, so the app has no key material to store or protect.
- The encrypted file can sit anywhere, including a readable file share. To other users it's just an unusable blob.
- This fits both scenarios. Each interactive user encrypts their own secrets. On the server, the secrets are encrypted *as the server's job account, on the server*.

### Rejected alternatives (don't revisit without a new reason)

| Option | Why not |
|---|---|
| Hashing | One-way. The apps need the raw values back to authenticate. |
| User-supplied "scope string" / passphrase-derived key | The string becomes the secret. If it's hardcoded, decompiling the .exe recovers it. If it's stored, that's the same problem again. If it's typed at runtime, unattended runs are impossible. |
| ASP.NET Core Data Protection API | Works in console apps, but it's a layer over DPAPI with its own key ring to manage. A key ring on a file share without `ProtectKeysWithDpapi()`/a certificate can be decrypted by anyone. Overkill here. |
| `DataProtectionScope.LocalMachine` | **Any** user on that machine can decrypt. Never use it. |
| Certificate encryption (`EnvelopedCms`) | Valid, and needed only if payloads must be generated *off* the target machine. Deferred. See "Future". |
| .NET User Secrets | Plain text, intended for development only. |

## Design

### Projects

```
Lockbox/              class library, target net10.0-windows
  ISecretProtector.cs         byte[] Protect(byte[], string context) / byte[] Unprotect(byte[], string context)
  DpapiUserProtector.cs       ProtectedData + CurrentUser + entropy
  SecretStore.cs              load/save named secrets to a JSON file
  SecretStoreException.cs     clear, actionable error messages
Lockbox.Tests/
Lockbox.Setup.WinForms/   GUI for entering secrets
samples/                  demonstration apps and mock server (milestone 4)
```

Keep `ISecretProtector` so a `CertificateProtector` can be added later without touching the apps.

### Secret file format

Default path is `%APPDATA%\<AppName>\secrets.json`. It can be overridden with config or `--secrets-path`, for example to point at a home folder on the file server.

```json
{
  "version": 1,
  "protector": "dpapi-user",
  "encryptedBy": { "account": "DOMAIN\\user", "sid": "S-1-5-...", "machine": "PC123" },
  "secrets": {
    "api.username": { "createdUtc": "...", "ciphertext": "<base64>" },
    "api.password": { "createdUtc": "...", "ciphertext": "<base64>" },
    "jira.pat":     { "createdUtc": "...", "ciphertext": "<base64>" }
  }
}
```

- `encryptedBy` is **diagnostic metadata only**, never used for security. When decryption fails, use it to explain why: *"This file was encrypted by DOMAIN\x on PC123; you are running as DOMAIN\y on SRV01. Re-run set-credentials as the account that will run the app."*
- **Entropy:** pass `optionalEntropy` = UTF-8 of `"<AppName>|<secretName>"`. This isn't a secret. It only stops other apps running as the same user from casually decrypting these blobs, and it binds each blob to its name, so swapped entries fail to decrypt. `SecretStore` passes this string to the protector as its `context`, so a future `CertificateProtector` must also bind to it.
- **One account per file:** `SetSecrets` refuses to add secrets to a file whose existing secrets were encrypted by another account (by SID, falling back to account name), because the file would end up partly unreadable. The fix is a different `--secrets-path`, or `Delete()` and then set everything again. Removing a secret leaves `encryptedBy` unchanged.

### Setup commands (in each app, or in a shared CLI)

- `set-credentials` prompts for each required secret with **masked console input**. Never accept secrets as command-line arguments, because they end up in shell history and process listings. Encrypt and save.
- `verify-credentials` decrypts each secret and reports OK/failed **without printing values**. For the API app, it also tries a token request and reports success/failure.
- `show-credentials-info` prints the path, the `encryptedBy` metadata, secret names and created dates. No values.

On the server, run these **as the job's Windows account on the server**, either by logging in as it or with `runas /user:SERVER\jobaccount "app.exe set-credentials"`.

The WinForms setup utility is just a GUI over the same `SecretStore`. It has the same rule: it must run as the account that will later run the app.

### App integration

**API export app**
- At startup, load `api.username` / `api.password`, then request a JWT.
- Keep the JWT **in memory only**. Never write it to disk.
- Add the header with a `DelegatingHandler`. There is no refresh endpoint, so if the token expires during a long export, log in again proactively (check `exp`), or on a 401 re-authenticate once and retry once.

**Jira export app**
- Load `jira.pat`. For Jira Server/Data Center, send `Authorization: Bearer <PAT>`. (Jira Cloud uses email + API token with Basic auth instead; the samples target Server/Data Center.)

### Security hygiene

- Never log secrets, the JWT or the `Authorization` header. Check that the HttpClient / `IHttpClientFactory` logging config redacts header values, and keep secrets out of exception messages.
- Don't try to zero managed strings. It isn't reliable in .NET, and the threat model doesn't need it.
- Restrict the folder holding the secrets file to the owning account. On the file server, that's the user plus admins.

## Operational notes for the server deployment (personal credentials)

- **Password change or PAT expiry → the job breaks.** Re-run `set-credentials` on the server as the job account. Note the PAT's expiry date, and consider having the app log a warning when auth starts failing.
- **Local vs domain Windows account:** if the job account is a *local* account and an admin *resets* its password (instead of the account changing it), existing DPAPI blobs become undecryptable. Domain accounts survive admin resets because the domain controller holds a backup key. Either way, re-running `set-credentials` fixes it.
- **Moving to another machine:** if the server or profile changes, encrypt again on the new machine. Blobs only move between machines when the profile roams.
- **Audit trail:** everything the server job does shows up in Jira and the API's logs as the person whose credentials it uses.
- **Threat model limit:** an admin on the server (or anyone who can run code as the job account) can recover the secrets. DPAPI protects against *other users*, not against admins.

## Future (out of scope unless needed)

- **`CertificateProtector`** with `EnvelopedCms` (`System.Security.Cryptography.Pkcs`). Encrypt with a public `.cer` anywhere and decrypt only where the private key is installed, for example the server job account's certificate store with the private key restricted to that account. Use it only if payloads must be generated on a different machine from the one that runs the app.
- Pull from an organisation secrets manager (Key Vault, Vault, CyberArk and so on) if one becomes available.

## Milestones

Milestones 1–4 and 8–10 are built in this repo. Milestones 5–7 happen in each consuming app's own solution, using the demonstration apps as the reference.

1. [x] `Lockbox` library (`net10.0-windows`): `ISecretProtector`, `DpapiUserProtector`, `SecretStore`, JSON format, diagnostic errors. *(Built and smoke-tested on Linux with a fake protector. The real DPAPI path still needs a run on Windows, covered by milestone 2.)*
2. [ ] Unit tests: round-trip, wrong entropy fails, missing secret, corrupt file, version handling (DPAPI tests are Windows-only, so mark or skip them elsewhere).
3. [ ] `set-credentials` / `verify-credentials` / `show-credentials-info` with masked input.
4. [ ] Demonstration apps, self-contained publish, runnable without the real services:
   - **Jira-style sample:** loads `jira.pat`, sends `Authorization: Bearer <pat>`.
   - **API-style sample:** loads `api.username` / `api.password`, logs in for a JWT, keeps it in memory only, adds it with a `DelegatingHandler`, re-logs in before `exp` and on a 401 (once, then retries once).
   - Both expose the setup commands from milestone 3 and redact `Authorization` in logs.
   - A small local mock server (login + protected endpoint, short-lived JWTs) so the samples can be run end to end, including token expiry.
5. [ ] *(consumer)* Integrate into a Jira app, following the Jira-style sample.
6. [ ] *(consumer)* Integrate into an API app, following the API-style sample.
7. [ ] *(consumer)* Remove any existing plain-text credential config from the consuming apps. Make sure secrets aren't committed in git history.
8. [ ] Server dry run: create the job account, run `set-credentials` as that account, run a scheduled trigger, confirm decryption and the export. Do it with a demonstration app first, then the consuming apps.
9. [ ] (Optional) WinForms setup utility.
10. [ ] README for end users and integrators: first-time setup, re-running after a password change, troubleshooting decryption errors, and how to add `Lockbox` to a new app.

## Decisions

- **Framework:** .NET 10. Published apps are self-contained and don't depend on an installed runtime.
- **Consumers:** apps live in separate solutions, and more will be added later, so `Lockbox` stays generic and app-agnostic. This repo holds the library and demonstration apps that show how a consuming app decrypts its credentials.
- **Jira:** Server/Data Center with a Bearer PAT.
- **API auth:** JWT from username + password. No refresh endpoint; re-login is required.

## Open questions

- **Server trigger:** Task Scheduler is assumed; a Windows service is possible. Document both in the README.
- **Job account:** local or domain. Both are covered in the operational notes.
- **Default secrets location for interactive users:** `%APPDATA%` (the current default) or a home folder on a file server (available through the path override).
