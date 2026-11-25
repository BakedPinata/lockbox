using Lockbox.Cli;
using Lockbox.Setup;
using static Lockbox.Tests.FakeConsole;

namespace Lockbox.Tests;

/// <summary>A process runner that returns scripted results and records what it was asked to run.</summary>
internal sealed class FakeRunner(Func<string, IReadOnlyList<string>, ProcessResult> respond) : IProcessRunner
{
    public List<(string FileName, string[] Arguments)> Calls { get; } = [];

    public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        Calls.Add((fileName, [.. arguments]));
        return Task.FromResult(respond(fileName, arguments));
    }
}

[TestClass]
public sealed class DescribeCredentialsTests : StoreTestBase
{
    private static readonly CredentialDefinition[] Definitions =
    [
        new("api.username", "Username", masked: false),
        new("api.password", "Pässwörd"),
    ];

    private CredentialCommands Commands(FakeConsole console, CredentialCheck? check = null) =>
        new(AppName, Definitions, console, path => Store(path: path ?? FilePath), TimeProvider.System) { ServiceCheck = check, ServiceName = "https://api.example/" };

    [TestMethod]
    public async Task DescribeOutputIsReadByTheSetupTool()
    {
        var console = new FakeConsole();

        Assert.AreEqual(0, await Commands(console, (_, _) => Task.FromResult(CredentialCheckResult.Success())).TryRunAsync(["describe-credentials"]));

        var description = AppDescription.Parse(console.Output);
        Assert.AreEqual(AppName, description.AppName);
        Assert.AreEqual(FilePath, description.SecretsPath);
        Assert.AreEqual("https://api.example/", description.ServiceName);
        Assert.IsTrue(description.HasServiceCheck);
        CollectionAssert.AreEqual(
            new[] { new CredentialField("api.username", "Username", false), new CredentialField("api.password", "Pässwörd", true) },
            description.Credentials.ToArray());
    }

    [TestMethod]
    public async Task DescribeOutputIsAscii()
    {
        var console = new FakeConsole();

        await Commands(console).TryRunAsync(["describe-credentials"]);

        Assert.IsTrue(console.Output.All(char.IsAscii), console.Output);
        Assert.IsFalse(AppDescription.Parse(console.Output).HasServiceCheck);
    }

    [TestMethod]
    public async Task DescribeHonoursSecretsPath()
    {
        var path = Path.Combine(Directory, "other.json");
        var console = new FakeConsole();

        await Commands(console).TryRunAsync(["describe-credentials", "--secrets-path", path]);

        Assert.AreEqual(path, AppDescription.Parse(console.Output).SecretsPath);
    }

    [TestMethod]
    public async Task DescribeNeverReadsOrPrintsValues()
    {
        Store().SetSecrets(new Dictionary<string, string> { ["api.username"] = "alice-user", ["api.password"] = "hunter2" });
        var console = new FakeConsole();

        await Commands(console).TryRunAsync(["describe-credentials"]);

        Assert.DoesNotContain("alice-user", console.AllText);
        Assert.DoesNotContain("hunter2", console.AllText);
    }

    [TestMethod]
    public void DescribeIsACredentialCommand() => Assert.IsTrue(CredentialCommands.IsCredentialCommand("describe-credentials"));

    [TestMethod]
    [DataRow("", DisplayName = "empty")]
    [DataRow("Usage: app <command>", DisplayName = "not JSON")]
    [DataRow("""{"format":"lockbox-credentials/2","appName":"A","secretsPath":"/x","credentials":[]}""", DisplayName = "newer format")]
    [DataRow("""{"format":"lockbox-credentials/1","appName":"A","secretsPath":"relative.json","credentials":[{"name":"a","prompt":"A","masked":true}]}""", DisplayName = "relative path")]
    [DataRow("""{"format":"lockbox-credentials/1","appName":"A|B","secretsPath":"/x","credentials":[{"name":"a","prompt":"A","masked":true}]}""", DisplayName = "bad app name")]
    [DataRow("""{"format":"lockbox-credentials/1","appName":"A","secretsPath":"/x","credentials":[]}""", DisplayName = "no credentials")]
    [DataRow("""{"format":"lockbox-credentials/1","appName":"A","secretsPath":"/x","credentials":[{"name":"a","prompt":"A","masked":true},{"name":"a","prompt":"B","masked":true}]}""", DisplayName = "duplicate")]
    [DataRow("""{"format":"lockbox-credentials/1","appName":"A","secretsPath":"/x","credentials":[{"name":"bad name","prompt":"A","masked":true}]}""", DisplayName = "bad secret name")]
    [DataRow("""{"format":"lockbox-credentials/1","appName":"A","secretsPath":"/x","credentials":[{"name":"a","masked":true}]}""", DisplayName = "no prompt")]
    [DataRow("{ broken", DisplayName = "broken JSON")]
    public void InvalidDescriptionsAreRejected(string output)
    {
        // Paths are only "full" relative to the OS; make the valid-looking ones full here.
        output = output.Replace("\"/x\"", System.Text.Json.JsonSerializer.Serialize(Path.GetFullPath("x.json")), StringComparison.Ordinal);

        Assert.ThrowsExactly<FormatException>(() => AppDescription.Parse(output));
    }

    [TestMethod]
    public void TextBeforeTheJsonIsIgnored()
    {
        var json = $$"""{"format":"lockbox-credentials/1","appName":"A","secretsPath":{{System.Text.Json.JsonSerializer.Serialize(Path.GetFullPath("x.json"))}},"credentials":[{"name":"a","prompt":"A","masked":true}]}""";

        Assert.AreEqual("A", AppDescription.Parse("Some banner\r\n" + json + "\r\n").AppName);
    }
}

[TestClass]
public sealed class TargetAppTests : StoreTestBase
{
    private string DescribeJson() =>
        $$"""{"format":"lockbox-credentials/1","appName":"SampleApp","secretsPath":{{System.Text.Json.JsonSerializer.Serialize(FilePath)}},"serviceName":"svc","hasServiceCheck":true,"credentials":[{"name":"a","prompt":"A","masked":true}]}""";

    [TestMethod]
    public async Task RunsAnExeDirectly()
    {
        var runner = new FakeRunner((_, _) => new ProcessResult(0, DescribeJson()));
        var app = new TargetApp(Path.Combine(Directory, "App.exe"), runner);

        var description = await app.DescribeAsync(null, default);

        Assert.AreEqual("SampleApp", description.AppName);
        Assert.AreEqual(Path.Combine(Directory, "App.exe"), runner.Calls[0].FileName);
        CollectionAssert.AreEqual(new[] { "describe-credentials" }, runner.Calls[0].Arguments);
    }

    [TestMethod]
    public async Task RunsADllWithDotnet()
    {
        var runner = new FakeRunner((_, _) => new ProcessResult(0, "ok"));
        var dll = Path.Combine(Directory, "App.dll");

        await new TargetApp(dll, runner).VerifyAsync(FilePath, default);

        Assert.AreEqual("dotnet", runner.Calls[0].FileName);
        CollectionAssert.AreEqual(new[] { dll, "verify-credentials", "--secrets-path", FilePath }, runner.Calls[0].Arguments);
    }

    [TestMethod]
    public async Task PassesTheSecretsPathToDescribe()
    {
        var runner = new FakeRunner((_, _) => new ProcessResult(0, DescribeJson()));

        await new TargetApp("App.exe", runner).DescribeAsync(FilePath, default);

        CollectionAssert.AreEqual(new[] { "describe-credentials", "--secrets-path", FilePath }, runner.Calls[0].Arguments);
    }

    [TestMethod]
    public async Task AnAppWithoutDescribeSupportIsExplained()
    {
        var runner = new FakeRunner((_, _) => new ProcessResult(2, "Usage: App <command>"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => new TargetApp("App.exe", runner).DescribeAsync(null, default));

        Assert.Contains("Lockbox.Cli 0.2 or later", ex.Message);
        Assert.Contains("Usage: App <command>", ex.Message);
    }

    [TestMethod]
    public async Task UnreadableDescriptionIsExplained()
    {
        var runner = new FakeRunner((_, _) => new ProcessResult(0, "hello"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => new TargetApp("App.exe", runner).DescribeAsync(null, default));

        Assert.Contains("App.exe", ex.Message);
    }

    [TestMethod]
    public async Task ProcessRunnerCapturesOutputAndExitCode()
    {
        var result = await new ProcessRunner().RunAsync("dotnet", ["--version"], TimeSpan.FromSeconds(60), default);

        Assert.AreEqual(0, result.ExitCode);
        Assert.IsTrue(Version.TryParse(result.Output.Trim().Split('-')[0], out _), result.Output);
    }

    [TestMethod]
    public async Task ProcessRunnerReportsAMissingProgram()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => new ProcessRunner().RunAsync(Path.Combine(Directory, "missing.exe"), [], TimeSpan.FromSeconds(5), default));

        Assert.Contains("couldn't be started", ex.Message);
    }

    [TestMethod]
    public async Task ProcessRunnerTimesOut()
    {
        var (file, args) = OperatingSystem.IsWindows()
            ? ("powershell", new[] { "-NoProfile", "-Command", "Start-Sleep 30" })
            : ("sleep", new[] { "30" });

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => new ProcessRunner().RunAsync(file, args, TimeSpan.FromSeconds(1), default));

        Assert.Contains("didn't finish within 1 seconds", ex.Message);
    }
}

[TestClass]
public sealed class SetupSessionTests : StoreTestBase
{
    private static readonly AppDescription Template = new(
        AppName,
        "placeholder",
        "svc",
        HasServiceCheck: false,
        [new CredentialField("api.username", "Username", false), new CredentialField("api.password", "Password", true)]);

    private readonly FixedTimeProvider _time = new(new DateTimeOffset(2026, 3, 1, 12, 0, 0, TimeSpan.Zero));

    private SetupSession Session(AccountInfo? account = null) =>
        new(Template with { SecretsPath = FilePath }, Store(account, time: _time), _time);

    private static Dictionary<string, string?> Entered(string? username, string? password) =>
        new() { ["api.username"] = username, ["api.password"] = password };

    [TestMethod]
    public void SavesNewCredentials()
    {
        var session = Session();

        Assert.AreEqual(new SaveResult.Saved(2), session.Save(Entered(" alice ", " pw "), replaceConfirmed: false));

        Assert.AreEqual("alice", Store().GetSecret("api.username"), "Visible values are trimmed.");
        Assert.AreEqual(" pw ", Store().GetSecret("api.password"), "Masked values are not.");
        Assert.AreEqual(SecretFileState.Usable, session.Status.FileState, "Status is refreshed after saving.");
        Assert.AreEqual("Set 2026-03-01 12:00 UTC (just now)", session.DescribeCredential("api.password"));
    }

    [TestMethod]
    public void BlankFieldsAreRequiredWhenThereIsNothingToKeep()
    {
        var result = Session().Save(Entered("alice", "  "), replaceConfirmed: false);

        Assert.AreEqual("api.password", ((SaveResult.ValuesRequired)result).Fields.Single().Name);
        Assert.IsFalse(Store().Exists);
    }

    [TestMethod]
    public void BlankFieldsKeepUsableValues()
    {
        Store().SetSecrets(new Dictionary<string, string> { ["api.username"] = "alice", ["api.password"] = "old" });
        var session = Session();

        Assert.IsTrue(session.CanKeep("api.username"));
        Assert.AreEqual(new SaveResult.Saved(1), session.Save(Entered("", "new"), replaceConfirmed: false));

        Assert.AreEqual("alice", Store().GetSecret("api.username"));
        Assert.AreEqual("new", Store().GetSecret("api.password"));
    }

    [TestMethod]
    public void AllBlankWithUsableValuesChangesNothing()
    {
        Store().SetSecrets(new Dictionary<string, string> { ["api.username"] = "alice", ["api.password"] = "pw" });
        var before = File.ReadAllText(FilePath);

        Assert.IsInstanceOfType<SaveResult.NothingChanged>(Session().Save(Entered(null, null), replaceConfirmed: false));
        Assert.AreEqual(before, File.ReadAllText(FilePath));
    }

    [TestMethod]
    public void AnotherAccountsFileNeedsConfirmationAndEveryValue()
    {
        Store(Accounts.Other).SetSecrets(new Dictionary<string, string> { ["api.username"] = "job", ["api.password"] = "pw", ["x"] = "1" });
        var before = File.ReadAllText(FilePath);
        var session = Session();

        Assert.Contains(@"encrypted by CONTOSO\job on SRV01", session.FileWarning!);
        Assert.IsFalse(session.CanKeep("api.username"));
        Assert.IsInstanceOfType<SaveResult.ValuesRequired>(session.Save(Entered("alice", null), replaceConfirmed: false));

        var confirm = session.Save(Entered("alice", "pw"), replaceConfirmed: false);
        Assert.Contains("Replace all 3 credential(s)", ((SaveResult.ReplaceConfirmationRequired)confirm).Question);
        Assert.AreEqual(before, File.ReadAllText(FilePath));

        Assert.AreEqual(new SaveResult.Saved(2), session.Save(Entered("alice", "pw"), replaceConfirmed: true));
        Assert.AreEqual(Accounts.Owner, Store().GetInfo().EncryptedBy);
        Assert.HasCount(2, Store().GetInfo().Secrets);
        Assert.IsNull(session.FileWarning);
    }

    [TestMethod]
    public void CorruptFileNeedsConfirmation()
    {
        WriteFile("{ nope");
        var session = Session();

        Assert.Contains("is damaged", session.FileWarning!);
        Assert.AreEqual("Unknown", session.DescribeCredential("api.username"));
        var confirm = (SaveResult.ReplaceConfirmationRequired)session.Save(Entered("a", "b"), replaceConfirmed: false);
        Assert.Contains("damaged", confirm.Question);
        Assert.AreEqual(new SaveResult.Saved(2), session.Save(Entered("a", "b"), replaceConfirmed: true));
    }

    [TestMethod]
    public void NewerFileIsNeverOverwritten()
    {
        WriteFile("""{"version":2}""");

        var result = Session().Save(Entered("a", "b"), replaceConfirmed: true);

        Assert.Contains("format version 2", ((SaveResult.Failed)result).Message);
        Assert.AreEqual("""{"version":2}""", File.ReadAllText(FilePath));
    }

    [TestMethod]
    public void DescribesEachCredential()
    {
        Store(time: _time).SetSecret("api.username", "alice");
        _time.Now = _time.Now.AddDays(2);

        var session = Session();

        Assert.AreEqual("Set 2026-03-01 12:00 UTC (2 days ago)", session.DescribeCredential("api.username"));
        Assert.AreEqual("Not set", session.DescribeCredential("api.password"));
        Assert.AreEqual(Accounts.Owner, session.CurrentAccount);
        Assert.AreEqual(FilePath, session.SecretsPath);
    }

    [TestMethod]
    public void DescribesAnUndecryptableCredential()
    {
        Store(Accounts.Other, time: _time).SetSecret("api.username", "job");

        Assert.AreEqual("Set 2026-03-01 12:00 UTC (just now), but can't be decrypted by this account", Session().DescribeCredential("api.username"));
    }
}

[TestClass]
public sealed class RunAsCommandTests
{
    [TestMethod]
    public void BuildsACommandWithEscapedQuotes() => Assert.AreEqual(
        """runas /user:SERVER\job "\"C:\Tools\LockboxSetup.exe\" --app \"C:\Apps\Jira Export\JiraExport.exe\"" """.TrimEnd(),
        RunAsCommand.Build(@" SERVER\job ", @"C:\Tools\LockboxSetup.exe", @"C:\Apps\Jira Export\JiraExport.exe", null));

    [TestMethod]
    public void IncludesTheSecretsPath() => Assert.EndsWith(
        """--secrets-path \"\\files\home\job\jira.json\"" """.TrimEnd(),
        RunAsCommand.Build(@"DOMAIN\job", "s.exe", "a.exe", @"\\files\home\job\jira.json"));

    [TestMethod]
    [DataRow("")]
    [DataRow("  ")]
    [DataRow("bad\"name")]
    public void RejectsBadAccounts(string account) =>
        Assert.ThrowsExactly<ArgumentException>(() => RunAsCommand.Build(account, "s.exe", "a.exe", null));
}
