using System.Text.Json;
using System.Windows.Forms;

namespace Lockbox.Setup.WinForms.Tests;

/// <summary>
/// Drives the real form on an STA thread with real DPAPI. The app being set up is faked: it "describes" two
/// credentials and "verifies" by reading them back with Lockbox.
/// </summary>
[TestClass]
public sealed class MainFormTests : IDisposable
{
    private const string AppName = "LockboxSetupTests";
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "lockbox-setup-tests-" + Guid.NewGuid().ToString("N"));
    private readonly FakePrompts _prompts = new();
    private readonly List<string[]> _calls = [];
    private int _describeExitCode;

    public MainFormTests() => Directory.CreateDirectory(_dir);

    private string SecretsPath => Path.Combine(_dir, "secrets.json");

    private SecretStore Store => new(AppName, SecretsPath);

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [STATestMethod]
    public void ShowsAFieldForEachCredential() => WithForm(form =>
    {
        CollectionAssert.AreEqual(new[] { "api.username", "api.password" }, form.Fields.Keys.ToArray());
        Assert.IsFalse(form.Fields["api.username"].Input.UseSystemPasswordChar);
        Assert.IsTrue(form.Fields["api.password"].Input.UseSystemPasswordChar);
        Assert.AreEqual("Not set", form.Fields["api.password"].Status.Text);
        Assert.AreEqual("Required", form.Fields["api.password"].Input.PlaceholderText);
        Assert.AreEqual(SecretsPath, form.SecretsPathLabel.Text);
        Assert.AreEqual(AccountInfo.GetCurrent().ToString(), form.AccountLabel.Text);
        Assert.IsTrue(form.SaveButton.Enabled);
        Assert.IsFalse(form.VerifyButton.Enabled, "Nothing to verify before the file exists.");
        Assert.IsFalse(form.WarningShown);
    });

    [STATestMethod]
    public void SaveEncryptsClearsTheFieldsAndVerifies() => WithForm(form =>
    {
        form.Fields["api.username"].Input.Text = "alice";
        form.Fields["api.password"].Input.Text = "p@ss wörd";

        Pump(form.SaveAsync());

        Assert.AreEqual("alice", Store.GetSecret("api.username"));
        Assert.AreEqual("p@ss wörd", Store.GetSecret("api.password"));
        Assert.AreEqual("", form.Fields["api.password"].Input.Text, "Values are cleared after saving.");
        Assert.StartsWith("Set ", form.Fields["api.password"].Status.Text);
        Assert.AreEqual("Leave blank to keep the current value", form.Fields["api.password"].Input.PlaceholderText);
        CollectionAssert.AreEqual(new[] { "verify-credentials", "--secrets-path", SecretsPath }, _calls[^1]);
        Assert.Contains("Saved 2 credentials.", form.Output.Text);
        Assert.Contains("Verification passed.", form.Output.Text);
        Assert.DoesNotContain("p@ss", form.Output.Text);
        Assert.IsTrue(form.VerifyButton.Enabled);
    });

    [STATestMethod]
    public void BlankRequiredFieldsAreReported() => WithForm(form =>
    {
        form.Fields["api.username"].Input.Text = "alice";

        Pump(form.SaveAsync());

        Assert.Contains("Password", _prompts.Errors.Single());
        Assert.IsFalse(File.Exists(SecretsPath));
        Assert.AreEqual("alice", form.Fields["api.username"].Input.Text, "Typed values are kept so the user can fix the form.");
    });

    [STATestMethod]
    public void CurrentValuesCanBeKept()
    {
        Store.SetSecrets(new Dictionary<string, string> { ["api.username"] = "alice", ["api.password"] = "old" });

        WithForm(form =>
        {
            Assert.AreEqual("Leave blank to keep the current value", form.Fields["api.username"].Input.PlaceholderText);
            form.Fields["api.password"].Input.Text = "new";

            Pump(form.SaveAsync());

            Assert.AreEqual("alice", Store.GetSecret("api.username"));
            Assert.AreEqual("new", Store.GetSecret("api.password"));
            Assert.Contains("Saved 1 credential.", form.Output.Text);
        });
    }

    [STATestMethod]
    public void AFileThatMustBeReplacedIsOnlyReplacedWithConsent()
    {
        // A file from another protector stands in for another account's file, which a test can't create.
        const string foreign = """{"version":1,"protector":"other","secrets":{"api.username":{"createdUtc":"2026-01-01T00:00:00Z","ciphertext":"AAAA"}}}""";
        File.WriteAllText(SecretsPath, foreign);

        WithForm(form =>
        {
            Assert.IsTrue(form.WarningShown);
            Assert.Contains("protector 'other'", form.Warning.Text);
            form.Fields["api.username"].Input.Text = "alice";
            form.Fields["api.password"].Input.Text = "pw";

            _prompts.ConfirmAnswer = false;
            Pump(form.SaveAsync());
            Assert.AreEqual(foreign, File.ReadAllText(SecretsPath));
            Assert.Contains("Replace all 1 credential(s)", _prompts.Questions.Single());

            _prompts.ConfirmAnswer = true;
            Pump(form.SaveAsync());
            Assert.AreEqual("pw", Store.GetSecret("api.password"));
            Assert.IsFalse(form.WarningShown);
        });
    }

    [STATestMethod]
    public void AnAppThatCannotDescribeItselfIsExplained()
    {
        _describeExitCode = 2;

        WithForm(form =>
        {
            Assert.IsTrue(form.WarningShown);
            Assert.Contains("couldn't describe its credentials", form.Warning.Text);
            Assert.IsFalse(form.SaveButton.Enabled);
            Assert.IsEmpty(form.Fields);
        });
    }

    [STATestMethod]
    public void RunAsCommandFollowsTheAccount() => WithForm(form =>
    {
        Assert.AreEqual("", form.RunAsCommandBox.Text);

        form.RunAsAccount.Text = @"SERVER\job";

        Assert.StartsWith(@"runas /user:SERVER\job ""\""C:\Tools\LockboxSetup.exe\"" --app \""", form.RunAsCommandBox.Text);
    });

    [STATestMethod]
    public void TheFormShowsAndCloses()
    {
        using var form = CreateForm();
        form.Show();
        Application.DoEvents();
        Assert.IsTrue(form.Visible);
        form.Close();
        Application.DoEvents();
    }

    private static void Pump(Task task)
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (!task.IsCompleted)
        {
            Application.DoEvents();
            Thread.Sleep(5);
            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException("The form's operation didn't finish.");
            }
        }

        task.GetAwaiter().GetResult();
    }

    private MainForm CreateForm()
    {
        SynchronizationContext.SetSynchronizationContext(new WindowsFormsSynchronizationContext());
        var runner = new DelegateRunner(args =>
        {
            _calls.Add([.. args]);
            if (args[0] == "describe-credentials")
            {
                return new ProcessResult(_describeExitCode, _describeExitCode == 0 ? DescribeJson() : "Usage: app <command>");
            }

            // "Verify" the way the real command does: decrypt every secret.
            var results = Store.CheckSecrets(["api.username", "api.password"]);
            return new ProcessResult(results.All(r => r.Succeeded) ? 0 : 1, string.Join(Environment.NewLine, results.Select(r => $"  {r.Name}  {(r.Succeeded ? "OK" : "FAILED")}")));
        });

        return new MainForm(
            @"C:\Apps\SampleApp.exe",
            null,
            _prompts,
            description => new SetupSession(description),
            path => new TargetApp(path, runner),
            @"C:\Tools\LockboxSetup.exe");
    }

    private void WithForm(Action<MainForm> test)
    {
        using var form = CreateForm();
        _ = form.Handle; // Create the window so controls work without showing it.
        Pump(form.LoadAsync());
        test(form);
    }

    private string DescribeJson() => JsonSerializer.Serialize(new
    {
        format = "lockbox-credentials/1",
        appName = AppName,
        secretsPath = SecretsPath,
        serviceName = "the test service",
        hasServiceCheck = false,
        credentials = new[]
        {
            new { name = "api.username", prompt = "Username", masked = false },
            new { name = "api.password", prompt = "Password", masked = true },
        },
    });

    private sealed class DelegateRunner(Func<IReadOnlyList<string>, ProcessResult> respond) : IProcessRunner
    {
        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromResult(respond(arguments));
    }

    private sealed class FakePrompts : IUserPrompts
    {
        public bool ConfirmAnswer { get; set; }

        public List<string> Questions { get; } = [];

        public List<string> Errors { get; } = [];

        public bool Confirm(IWin32Window owner, string message)
        {
            Questions.Add(message);
            return ConfirmAnswer;
        }

        public void ShowError(IWin32Window owner, string message) => Errors.Add(message);

        public void ShowInfo(IWin32Window owner, string message)
        {
        }

        public string? ChooseApp(IWin32Window owner) => null;

        public string? ChooseSecretsPath(IWin32Window owner, string current) => null;

        public void CopyToClipboard(string text)
        {
        }
    }
}
