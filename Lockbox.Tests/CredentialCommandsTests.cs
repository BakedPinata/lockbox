using System.Text.Json.Nodes;
using Lockbox.Cli;
using static Lockbox.Tests.FakeConsole;

namespace Lockbox.Tests;

[TestClass]
public sealed class CredentialCommandsTests : StoreTestBase
{
    private const string Password = "p@ss wörd";

    private static readonly CredentialDefinition[] Definitions =
    [
        new("api.username", "Username", masked: false),
        new("api.password", "Password"),
    ];

    private CredentialCommands Commands(
        FakeConsole console,
        AccountInfo? account = null,
        CredentialCheck? check = null,
        TimeProvider? time = null) =>
        new(AppName, Definitions, console, path => Store(account, time: time, path: path ?? FilePath), time ?? TimeProvider.System)
        {
            ServiceCheck = check,
            ServiceName = "the test service",
        };

    private Task<int?> Run(FakeConsole console, params string[] args) => Commands(console).TryRunAsync(args);

    private void SaveBoth(AccountInfo? account = null) =>
        Store(account).SetSecrets(new Dictionary<string, string> { ["api.username"] = "alice", ["api.password"] = Password });

    [TestMethod]
    [DataRow(new string[0], DisplayName = "no args")]
    [DataRow(new[] { "export" }, DisplayName = "app command")]
    [DataRow(new[] { "--secrets-path", "x", "set-credentials" }, DisplayName = "command not first")]
    [DataRow(new[] { "Set-Credentials" }, DisplayName = "wrong case")]
    public async Task OtherArgumentsAreLeftToTheApp(string[] args)
    {
        var console = new FakeConsole();

        Assert.IsNull(await Run(console, args));
        Assert.AreEqual("", console.AllText);
    }

    [TestMethod]
    public void IsCredentialCommand()
    {
        Assert.IsTrue(CredentialCommands.IsCredentialCommand("set-credentials"));
        Assert.IsTrue(CredentialCommands.IsCredentialCommand("verify-credentials"));
        Assert.IsTrue(CredentialCommands.IsCredentialCommand("show-credentials-info"));
        Assert.IsFalse(CredentialCommands.IsCredentialCommand("export"));
        Assert.IsFalse(CredentialCommands.IsCredentialCommand(null));
    }

    // set-credentials

    [TestMethod]
    public async Task SetCredentialsPromptsSavesAndVerifies()
    {
        var console = new FakeConsole(Line("alice"), Masked(Password));

        Assert.AreEqual(0, await Run(console, "set-credentials"));

        Assert.AreEqual("alice", Store().GetSecret("api.username"));
        Assert.AreEqual(Password, Store().GetSecret("api.password"));
        Assert.Contains($"Secrets file:  {FilePath}", console.Output);
        Assert.Contains(@"Encrypting as: CONTOSO\alice on PC01", console.Output);
        Assert.Contains("Username: ", console.Output);
        Assert.Contains("Password: ", console.Output);
        Assert.Contains("Saved 2 credentials.", console.Output);
        Assert.Contains("  api.username  OK", console.Output);
        Assert.Contains("  api.password  OK", console.Output);
        Assert.DoesNotContain(Password, console.AllText);
    }

    [TestMethod]
    public async Task VisibleValuesAreTrimmedMaskedValuesAreNot()
    {
        var console = new FakeConsole(Line("  alice  "), Masked(" pass "));

        Assert.AreEqual(0, await Run(console, "set-credentials"));

        Assert.AreEqual("alice", Store().GetSecret("api.username"));
        Assert.AreEqual(" pass ", Store().GetSecret("api.password"));
    }

    [TestMethod]
    public async Task EmptyValuesArePromptedAgain()
    {
        var console = new FakeConsole(Line(""), Line("   "), Line("alice"), Masked(""), Masked(Password));

        Assert.AreEqual(0, await Run(console, "set-credentials"));

        Assert.AreEqual(Password, Store().GetSecret("api.password"));
        Assert.AreEqual(3, console.Output.Split("A value is required.").Length - 1);
    }

    [TestMethod]
    public async Task CancellingAtAPromptSavesNothing()
    {
        var console = new FakeConsole(Line("alice"), Masked(null));

        Assert.AreEqual(1, await Run(console, "set-credentials"));

        Assert.IsFalse(Store().Exists);
        Assert.Contains("Cancelled. Nothing was saved.", console.Errors);
    }

    [TestMethod]
    public async Task EndOfInputSavesNothing()
    {
        var console = new FakeConsole();

        Assert.AreEqual(1, await Run(console, "set-credentials"));

        Assert.IsFalse(Store().Exists);
    }

    [TestMethod]
    public async Task CurrentValuesCanBeKept()
    {
        SaveBoth();
        var console = new FakeConsole(Line(""), Masked("new password"));

        Assert.AreEqual(0, await Run(console, "set-credentials"));

        Assert.AreEqual("alice", Store().GetSecret("api.username"));
        Assert.AreEqual("new password", Store().GetSecret("api.password"));
        Assert.Contains("Username (Enter to keep the current value): ", console.Output);
        Assert.Contains("Saved 1 credential.", console.Output);
    }

    [TestMethod]
    public async Task KeepingEverythingChangesNothing()
    {
        SaveBoth();
        var before = File.ReadAllText(FilePath);
        var console = new FakeConsole(Line(""), Masked(""));

        Assert.AreEqual(0, await Run(console, "set-credentials"));

        Assert.Contains("Nothing changed.", console.Output);
        Assert.AreEqual(before, File.ReadAllText(FilePath));
    }

    [TestMethod]
    public async Task ValuesThatDoNotDecryptCannotBeKept()
    {
        SaveBoth();
        var root = JsonNode.Parse(File.ReadAllText(FilePath))!;
        root["secrets"]!["api.password"]!["ciphertext"] = root["secrets"]!["api.username"]!["ciphertext"]!.DeepClone();
        WriteFile(root.ToJsonString());

        // Enter on the password is refused because the current value is unusable.
        var console = new FakeConsole(Line(""), Masked(""), Masked(Password));

        Assert.AreEqual(0, await Run(console, "set-credentials"));

        Assert.Contains("Password: ", console.Output);
        Assert.DoesNotContain("Password (Enter to keep", console.Output);
        Assert.AreEqual(Password, Store().GetSecret("api.password"));
    }

    [TestMethod]
    public async Task AnotherAccountsFileIsNotReplacedWithoutConsent()
    {
        SaveBoth(Accounts.Other);
        var before = File.ReadAllText(FilePath);
        var console = new FakeConsole(Line("n"));

        Assert.AreEqual(1, await Run(console, "set-credentials"));

        Assert.Contains(@"encrypted by CONTOSO\job on SRV01", console.Output);
        Assert.Contains("Nothing was changed.", console.Errors);
        Assert.AreEqual(before, File.ReadAllText(FilePath));
    }

    [TestMethod]
    public async Task AnotherAccountsFileCanBeReplaced()
    {
        SaveBoth(Accounts.Other);
        Store(Accounts.Other).SetSecret("jira.pat", "token");
        var console = new FakeConsole(Line("y"), Line("alice"), Masked(Password));

        Assert.AreEqual(0, await Run(console, "set-credentials"));

        var info = Store().GetInfo();
        Assert.AreEqual(Accounts.Owner, info.EncryptedBy);
        CollectionAssert.AreEqual(new[] { "api.password", "api.username" }, info.Secrets.Select(s => s.Name).ToArray());
        Assert.Contains("Replace all 3 credential(s)", console.Output);
    }

    [TestMethod]
    public async Task ReplacementIsOnlyAppliedOnceEverythingIsEntered()
    {
        SaveBoth(Accounts.Other);
        var before = File.ReadAllText(FilePath);
        var console = new FakeConsole(Line("yes"), Line("alice"), Masked(null));

        Assert.AreEqual(1, await Run(console, "set-credentials"));

        Assert.AreEqual(before, File.ReadAllText(FilePath));
    }

    [TestMethod]
    public async Task AnotherProtectorsFileCanBeReplaced()
    {
        Store(protector: new FakeProtector(Accounts.Owner, id: "other")).SetSecret("api.username", "x");
        var console = new FakeConsole(Line("y"), Line("alice"), Masked(Password));

        Assert.AreEqual(0, await Run(console, "set-credentials"));

        Assert.Contains("encrypted with 'other', not 'fake'", console.Output);
        Assert.AreEqual("fake", Store().GetInfo().Protector);
    }

    [TestMethod]
    public async Task CorruptFileCanBeReplaced()
    {
        WriteFile("{ not json");
        var console = new FakeConsole(Line("y"), Line("alice"), Masked(Password));

        Assert.AreEqual(0, await Run(console, "set-credentials"));

        Assert.Contains("is damaged", console.Output);
        Assert.AreEqual(Password, Store().GetSecret("api.password"));
    }

    [TestMethod]
    public async Task NewerFileIsRefused()
    {
        const string json = """{"version":2,"protector":"fake","secrets":{}}""";
        WriteFile(json);
        var console = new FakeConsole(Line("alice"), Masked(Password));

        Assert.AreEqual(1, await Run(console, "set-credentials"));

        Assert.Contains("format version 2", console.Errors);
        Assert.AreEqual(2, console.Remaining, "No prompts should be shown.");
        Assert.AreEqual(json, File.ReadAllText(FilePath));
    }

    [TestMethod]
    public async Task SetCredentialsRunsTheServiceCheck()
    {
        IReadOnlyDictionary<string, string>? seen = null;
        var console = new FakeConsole(Line("alice"), Masked(Password));
        var commands = Commands(console, check: (values, _) =>
        {
            seen = values;
            return Task.FromResult(CredentialCheckResult.Failure("HTTP 401"));
        });

        Assert.AreEqual(1, await commands.TryRunAsync(["set-credentials"]));

        Assert.AreEqual(Password, seen!["api.password"]);
        Assert.Contains("Checking with the test service... FAILED", console.Output);
        Assert.Contains("  HTTP 401", console.Output);
        Assert.AreEqual(Password, Store().GetSecret("api.password"), "Values are saved even if the service rejects them.");
    }

    // Arguments

    [TestMethod]
    [DataRow("set-credentials", "hunter2")]
    [DataRow("set-credentials", "--password=hunter2")]
    [DataRow("verify-credentials", "--password", "hunter2")]
    [DataRow("show-credentials-info", "-p", "hunter2")]
    public async Task UnexpectedArgumentsAreRejectedWithoutEchoingThem(params string[] args)
    {
        var console = new FakeConsole();

        Assert.AreEqual(2, await Run(console, args));

        Assert.Contains("Secrets are never accepted on the command line", console.Errors);
        Assert.DoesNotContain("hunter2", console.AllText);
        Assert.IsFalse(Store().Exists);
    }

    [TestMethod]
    [DataRow("--secrets-path")]
    [DataRow("--secrets-path=")]
    [DataRow("--secrets-path", "--other")]
    public async Task SecretsPathWithoutAValueIsAUsageError(params string[] options)
    {
        var console = new FakeConsole();

        Assert.AreEqual(2, await Run(console, ["verify-credentials", .. options]));

        Assert.Contains("--secrets-path needs a path", console.Errors);
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task SecretsPathOptionIsUsed(bool equalsForm)
    {
        var path = Path.Combine(Directory, "custom", "secrets.json");
        string[] options = equalsForm ? [$"--secrets-path={path}"] : ["--secrets-path", path];
        var console = new FakeConsole(Line("alice"), Masked(Password));

        Assert.AreEqual(0, await Run(console, ["set-credentials", .. options]));

        Assert.IsTrue(File.Exists(path));
        Assert.IsFalse(Store().Exists);
        Assert.Contains($"Secrets file:  {path}", console.Output);
    }

    [TestMethod]
    [DataRow("--help")]
    [DataRow("-h")]
    [DataRow("-?")]
    public async Task HelpIsShown(string option)
    {
        var console = new FakeConsole();

        Assert.AreEqual(0, await Run(console, "set-credentials", option));

        Assert.Contains("Credential commands:", console.Output);
        Assert.IsFalse(Store().Exists);
    }

    [TestMethod]
    public void UsageDescribesCommandsAndTheDefaultPath()
    {
        var writer = new StringWriter();
        new CredentialCommands(AppName, Definitions).WriteUsage(writer);
        var usage = writer.ToString();

        Assert.Contains("set-credentials", usage);
        Assert.Contains("verify-credentials", usage);
        Assert.Contains("show-credentials-info", usage);
        Assert.Contains(@"%APPDATA%\SampleApp\secrets.json", usage);

        writer = new StringWriter();
        new CredentialCommands(AppName, Definitions) { SecretsPath = @"\\server\home\secrets.json" }.WriteUsage(writer);
        Assert.Contains(@"\\server\home\secrets.json", writer.ToString());
    }

    // verify-credentials

    [TestMethod]
    public async Task VerifySucceeds()
    {
        SaveBoth();
        var console = new FakeConsole();

        Assert.AreEqual(0, await Run(console, "verify-credentials"));

        Assert.Contains(@"Running as:    CONTOSO\alice on PC01", console.Output);
        Assert.Contains("  api.username  OK", console.Output);
        Assert.Contains("  api.password  OK", console.Output);
        Assert.DoesNotContain(Password, console.AllText);
        Assert.DoesNotContain("alice\n", console.AllText.ReplaceLineEndings("\n"));
    }

    [TestMethod]
    public async Task VerifyWithoutAFileFails()
    {
        var console = new FakeConsole();

        Assert.AreEqual(1, await Run(console, "verify-credentials"));

        Assert.Contains("No secrets file was found", console.Errors);
    }

    [TestMethod]
    public async Task VerifyReportsMissingSecrets()
    {
        Store().SetSecret("api.username", "alice");
        var console = new FakeConsole();

        Assert.AreEqual(1, await Run(console, "verify-credentials"));

        Assert.Contains("  api.username  OK", console.Output);
        Assert.Contains("  api.password  FAILED", console.Output);
        Assert.Contains("The secret 'api.password' isn't in", console.Output);
    }

    [TestMethod]
    public async Task VerifyAsAnotherAccountExplainsWhy()
    {
        SaveBoth();
        var console = new FakeConsole();

        Assert.AreEqual(1, await Commands(console, Accounts.Other).TryRunAsync(["verify-credentials"]));

        Assert.Contains(@"This file was encrypted by CONTOSO\alice on PC01; you are running as CONTOSO\job on SRV01.", console.Output);
    }

    [TestMethod]
    public async Task VerifyRunsTheServiceCheckWithDecryptedValues()
    {
        SaveBoth();
        IReadOnlyDictionary<string, string>? seen = null;
        var console = new FakeConsole();
        var commands = Commands(console, check: (values, _) =>
        {
            seen = values;
            return Task.FromResult(CredentialCheckResult.Success("Signed in as alice"));
        });

        Assert.AreEqual(0, await commands.TryRunAsync(["verify-credentials"]));

        Assert.AreEqual("alice", seen!["api.username"]);
        Assert.AreEqual(Password, seen["api.password"]);
        Assert.Contains("Checking with the test service... OK", console.Output);
        Assert.Contains("  Signed in as alice", console.Output);
    }

    [TestMethod]
    public async Task ServiceCheckIsSkippedWhenSecretsDoNotDecrypt()
    {
        Store().SetSecret("api.username", "alice");
        var called = false;
        var console = new FakeConsole();
        var commands = Commands(console, check: (_, _) =>
        {
            called = true;
            return Task.FromResult(CredentialCheckResult.Success());
        });

        Assert.AreEqual(1, await commands.TryRunAsync(["verify-credentials"]));

        Assert.IsFalse(called);
    }

    [TestMethod]
    public async Task ServiceCheckExceptionsAreReported()
    {
        SaveBoth();
        var console = new FakeConsole();
        var commands = Commands(console, check: (_, _) => throw new HttpRequestException("No such host is known."));

        Assert.AreEqual(1, await commands.TryRunAsync(["verify-credentials"]));

        Assert.Contains("Checking with the test service... FAILED", console.Output);
        Assert.Contains("  HttpRequestException: No such host is known.", console.Output);
    }

    [TestMethod]
    public async Task ServiceCheckCancellationPropagates()
    {
        SaveBoth();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var commands = Commands(new FakeConsole(), check: async (_, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return CredentialCheckResult.Success();
        });

        await Assert.ThrowsAsync<OperationCanceledException>(() => commands.TryRunAsync(["verify-credentials"], cts.Token));
    }

    // show-credentials-info

    [TestMethod]
    public async Task ShowInfoListsCredentialsWithoutValues()
    {
        var time = new FixedTimeProvider(new DateTimeOffset(2026, 1, 1, 9, 30, 0, TimeSpan.Zero));
        Store(time: time).SetSecrets(new Dictionary<string, string> { ["api.username"] = "alice", ["old.token"] = "zzz-token" });
        time.Now = time.Now.AddDays(3).AddHours(2);
        var console = new FakeConsole();

        Assert.AreEqual(0, await Commands(console, time: time).TryRunAsync(["show-credentials-info"]));

        var output = console.Output;
        Assert.Contains($"Secrets file:  {FilePath}", output);
        Assert.Contains("Protector:     fake", output);
        Assert.Contains(@"Encrypted by:  CONTOSO\alice on PC01 (S-1-5-21-1000-1001)", output);
        Assert.Contains(@"Running as:    CONTOSO\alice on PC01", output);
        Assert.Contains("  api.username  set 2026-01-01 09:30 UTC (3 days ago)", output);
        Assert.Contains("  api.password  missing", output);
        Assert.Contains("  old.token     set 2026-01-01 09:30 UTC (3 days ago), not used by this app", output);
        Assert.DoesNotContain("zzz-token", console.AllText);
        Assert.DoesNotContain("can't decrypt", output);
    }

    [TestMethod]
    [DataRow(30, "just now")]
    [DataRow(60, "1 minute ago")]
    [DataRow(150, "2 minutes ago")]
    [DataRow(3600, "1 hour ago")]
    [DataRow(86400, "1 day ago")]
    [DataRow(86400 * 45, "45 days ago")]
    public async Task ShowInfoDescribesAge(int seconds, string expected)
    {
        var time = new FixedTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        SaveBothAt(time);
        time.Now = time.Now.AddSeconds(seconds);
        var console = new FakeConsole();

        await Commands(console, time: time).TryRunAsync(["show-credentials-info"]);

        Assert.Contains($"({expected})", console.Output);
    }

    [TestMethod]
    public async Task ShowInfoWarnsAnotherAccount()
    {
        SaveBoth();
        var console = new FakeConsole();

        Assert.AreEqual(0, await Commands(console, Accounts.Other).TryRunAsync(["show-credentials-info"]));

        Assert.Contains(@"This account can't decrypt these credentials. Run the app as CONTOSO\alice,", console.Output);
    }

    [TestMethod]
    public async Task ShowInfoWarnsAnotherMachine()
    {
        SaveBoth();
        var console = new FakeConsole();

        Assert.AreEqual(0, await Commands(console, Accounts.OwnerElsewhere).TryRunAsync(["show-credentials-info"]));

        Assert.Contains("Encrypted on PC01. They only decrypt here with a roaming profile.", console.Output);
    }

    [TestMethod]
    public async Task ShowInfoWithoutAFile()
    {
        var console = new FakeConsole();

        Assert.AreEqual(1, await Run(console, "show-credentials-info"));

        Assert.Contains("(doesn't exist yet)", console.Output);
        Assert.Contains("Run set-credentials as the account that will run the app", console.Output);
    }

    [TestMethod]
    public async Task ShowInfoWithACorruptFile()
    {
        WriteFile("[]");
        var console = new FakeConsole();

        Assert.AreEqual(1, await Run(console, "show-credentials-info"));

        Assert.Contains("is damaged", console.Errors);
    }

    // Store selection and construction

    [TestMethod]
    public void CreateStoreUsesTheOptionThenConfigThenDefault()
    {
        var commands = new CredentialCommands(AppName, Definitions);
        var configured = new CredentialCommands(AppName, Definitions) { SecretsPath = Path.Combine(Directory, "config.json") };
        var fromArgs = Path.Combine(Directory, "args.json");

        Assert.AreEqual(SecretStore.GetDefaultPath(AppName), commands.CreateStore(["export"]).FilePath);
        Assert.AreEqual(Path.Combine(Directory, "config.json"), configured.CreateStore(["export"]).FilePath);
        Assert.AreEqual(fromArgs, configured.CreateStore(["export", "--secrets-path", fromArgs, "--verbose"]).FilePath);
        Assert.AreEqual(AppName, commands.CreateStore([]).AppName);
    }

    [TestMethod]
    public void FindSecretsPath()
    {
        Assert.IsNull(CredentialCommands.FindSecretsPath(["export", "--verbose"]));
        Assert.AreEqual("a", CredentialCommands.FindSecretsPath(["--secrets-path", "a"]));
        Assert.AreEqual("b", CredentialCommands.FindSecretsPath(["--secrets-path=b"]));
        Assert.AreEqual("c", CredentialCommands.FindSecretsPath(["--secrets-path", "a", "--secrets-path=c"]));
        Assert.ThrowsExactly<ArgumentException>(() => CredentialCommands.FindSecretsPath(["--secrets-path"]));
        Assert.ThrowsExactly<ArgumentException>(() => CredentialCommands.FindSecretsPath(["--secrets-path", "--x"]));
        Assert.ThrowsExactly<ArgumentException>(() => CredentialCommands.FindSecretsPath(["--secrets-path="]));
    }

    [TestMethod]
    public void ConstructorValidates()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new CredentialCommands(AppName, []));
        Assert.ThrowsExactly<ArgumentException>(() => new CredentialCommands(AppName, [new("a", "A"), new("a", "Again")]));
        Assert.ThrowsExactly<ArgumentException>(() => new CredentialCommands("bad|name", Definitions));
        Assert.ThrowsExactly<ArgumentException>(() => new CredentialDefinition("bad name", "Prompt"));
        Assert.ThrowsExactly<ArgumentException>(() => new CredentialDefinition("ok", " "));
    }

    private void SaveBothAt(TimeProvider time) =>
        Store(time: time).SetSecrets(new Dictionary<string, string> { ["api.username"] = "alice", ["api.password"] = Password });
}
