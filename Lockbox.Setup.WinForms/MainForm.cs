using System.Drawing;

namespace Lockbox.Setup.WinForms;

/// <summary>
/// Enter an app's credentials, encrypt them for the current Windows account, and verify them with the app itself.
/// Values are never displayed or written anywhere except, encrypted, to the secrets file.
/// </summary>
internal sealed class MainForm : Form
{
    private readonly IUserPrompts _prompts;
    private readonly Func<AppDescription, SetupSession> _createSession;
    private readonly Func<string, TargetApp> _createApp;
    private readonly string _setupToolPath;

    private readonly Label _appPath = ValueLabel();
    private readonly Label _secretsPath = ValueLabel();
    private readonly Label _account = ValueLabel();
    private readonly Label _warning = new()
    {
        AutoSize = true,
        Visible = false,
        ForeColor = Color.DarkRed,
        Padding = new Padding(0, 6, 0, 6),
        MaximumSize = new Size(700, 0),
    };

    private readonly TableLayoutPanel _fieldsTable = new()
    {
        ColumnCount = 3,
        AutoSize = true,
        Dock = DockStyle.Fill,
        Padding = new Padding(6),
    };

    private readonly Button _chooseApp = new() { Text = "Choose app…", AutoSize = true };
    private readonly Button _changeSecretsPath = new() { Text = "Change…", AutoSize = true, Enabled = false };
    private readonly TextBox _runAsAccount = new() { Width = 220, PlaceholderText = @"e.g. SERVER\jobaccount" };
    private readonly TextBox _runAsCommand = new() { ReadOnly = true, Dock = DockStyle.Fill };
    private readonly Button _copyRunAs = new() { Text = "Copy", AutoSize = true, Enabled = false };
    private readonly Button _save = new() { Text = "&Save", AutoSize = true, Enabled = false };
    private readonly Button _verify = new() { Text = "&Verify", AutoSize = true, Enabled = false };
    private readonly Button _close = new() { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
    private readonly TextBox _output = new()
    {
        Multiline = true,
        ReadOnly = true,
        ScrollBars = ScrollBars.Vertical,
        Dock = DockStyle.Fill,
        Font = new Font(FontFamily.GenericMonospace, 9f),
        MinimumSize = new Size(0, 120),
    };

    private readonly Dictionary<string, (TextBox Input, Label Status)> _fields = new(StringComparer.Ordinal);
    private TargetApp? _app;
    private string? _secretsPathOverride;
    private bool _busy;

    public MainForm(
        string? appPath,
        string? secretsPath,
        IUserPrompts prompts,
        Func<AppDescription, SetupSession> createSession,
        Func<string, TargetApp> createApp,
        string setupToolPath)
    {
        _prompts = prompts;
        _createSession = createSession;
        _createApp = createApp;
        _setupToolPath = setupToolPath;
        _secretsPathOverride = secretsPath;
        _app = appPath is null ? null : createApp(appPath);

        Text = "Lockbox Setup";
        AutoScaleMode = AutoScaleMode.Dpi;
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(640, 520);
        Size = new Size(760, 640);
        AcceptButton = _save;
        CancelButton = _close;
        Controls.Add(BuildLayout());

        _chooseApp.Click += async (_, _) => await ChooseAppAsync();
        _changeSecretsPath.Click += async (_, _) => await ChangeSecretsPathAsync();
        _save.Click += async (_, _) => await SaveAsync();
        _verify.Click += async (_, _) => await VerifyAsync();
        _close.Click += (_, _) => Close();
        _runAsAccount.TextChanged += (_, _) => UpdateRunAsCommand();
        _copyRunAs.Click += (_, _) => _prompts.CopyToClipboard(_runAsCommand.Text);
        Shown += async (_, _) => await LoadAsync();
        FormClosed += (_, _) => ClearInputs();
    }

    internal SetupSession? Session { get; private set; }

    internal IReadOnlyDictionary<string, (TextBox Input, Label Status)> Fields => _fields;

    internal Label Warning => _warning;

    internal TextBox Output => _output;

    internal Button SaveButton => _save;

    internal Button VerifyButton => _verify;

    internal TextBox RunAsAccount => _runAsAccount;

    internal TextBox RunAsCommandBox => _runAsCommand;

    internal Label AccountLabel => _account;

    internal Label SecretsPathLabel => _secretsPath;

    /// <summary>Asks the app to describe its credentials and shows a field for each. Asks for the app first if none was given.</summary>
    internal async Task LoadAsync()
    {
        if (_app is null)
        {
            await ChooseAppAsync();
            return;
        }

        _appPath.Text = _app.Path;
        SetBusy(true);
        try
        {
            var description = await _app.DescribeAsync(_secretsPathOverride, CancellationToken.None);
            Session = _createSession(description);
            Render();
        }
        catch (InvalidOperationException ex)
        {
            Session = null;
            Render();
            ShowWarning(ex.Message);
        }
        finally
        {
            SetBusy(false);
        }
    }

    internal async Task SaveAsync()
    {
        if (Session is null || _busy)
        {
            return;
        }

        var entered = _fields.ToDictionary(f => f.Key, f => (string?)f.Value.Input.Text, StringComparer.Ordinal);
        var result = Session.Save(entered, replaceConfirmed: false);
        if (result is SaveResult.ReplaceConfirmationRequired confirm)
        {
            if (!_prompts.Confirm(this, confirm.Question))
            {
                return;
            }

            result = Session.Save(entered, replaceConfirmed: true);
        }

        switch (result)
        {
            case SaveResult.ValuesRequired required:
                _prompts.ShowError(this, "Enter a value for:" + Environment.NewLine + string.Join(Environment.NewLine, required.Fields.Select(f => "  " + f.Prompt)));
                _fields[required.Fields[0].Name].Input.Focus();
                return;

            case SaveResult.Failed failed:
                _prompts.ShowError(this, failed.Message);
                Render();
                return;

            case SaveResult.NothingChanged:
                AppendOutput("Nothing changed: every field was left blank, so the current values were kept.");
                break;

            case SaveResult.Saved saved:
                AppendOutput(saved.Count == 1 ? "Saved 1 credential." : $"Saved {saved.Count} credentials.");
                break;
        }

        ClearInputs();
        Render();
        await VerifyAsync();
    }

    /// <summary>Runs the app's own <c>verify-credentials</c>, which decrypts each secret and checks it with the service.</summary>
    internal async Task VerifyAsync()
    {
        if (Session is null || _app is null || _busy)
        {
            return;
        }

        SetBusy(true);
        try
        {
            AppendOutput($"Running {Path.GetFileName(_app.Path)} verify-credentials…");
            var result = await _app.VerifyAsync(Session.SecretsPath, CancellationToken.None);
            AppendOutput(result.Output.TrimEnd());
            AppendOutput(result.ExitCode == 0 ? "Verification passed." : $"Verification failed (exit code {result.ExitCode}).");
        }
        catch (InvalidOperationException ex)
        {
            AppendOutput(ex.Message);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private static Label ValueLabel() => new() { AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(0, 4, 0, 4) };

    private static Label CaptionLabel(string text) => new() { Text = text, AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(0, 4, 0, 4) };

    private TableLayoutPanel BuildLayout()
    {
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(12) };

        var header = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, AutoSize = true };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        header.Controls.Add(CaptionLabel("App:"), 0, 0);
        header.Controls.Add(_appPath, 1, 0);
        header.Controls.Add(_chooseApp, 2, 0);
        header.Controls.Add(CaptionLabel("Secrets file:"), 0, 1);
        header.Controls.Add(_secretsPath, 1, 1);
        header.Controls.Add(_changeSecretsPath, 2, 1);
        header.Controls.Add(CaptionLabel("Encrypting as:"), 0, 2);
        header.Controls.Add(_account, 1, 2);

        var explanation = new Label
        {
            AutoSize = true,
            MaximumSize = new Size(700, 0),
            Padding = new Padding(0, 6, 0, 0),
            Text = "Only this Windows account can decrypt the credentials you save here. If the app runs as a different account " +
                   "(for example a scheduled task), run this tool as that account. Use \"Run as another account\" below.",
        };

        _fieldsTable.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        _fieldsTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        _fieldsTable.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var credentials = new GroupBox { Text = "Credentials", Dock = DockStyle.Fill, AutoSize = true, Padding = new Padding(6) };
        credentials.Controls.Add(_fieldsTable);

        var runAs = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, AutoSize = true, Padding = new Padding(6) };
        runAs.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        runAs.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        runAs.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        runAs.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        runAs.Controls.Add(CaptionLabel("Account:"), 0, 0);
        runAs.Controls.Add(_runAsAccount, 1, 0);
        runAs.Controls.Add(_runAsCommand, 2, 0);
        runAs.Controls.Add(_copyRunAs, 3, 0);
        var runAsGroup = new GroupBox { Text = "Run as another account", Dock = DockStyle.Fill, AutoSize = true, Padding = new Padding(6) };
        runAsGroup.Controls.Add(runAs);
        _runAsAccount.AccessibleName = "Account to run as";
        _runAsCommand.AccessibleName = "runas command";

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.LeftToRight, Padding = new Padding(0, 6, 0, 6) };
        buttons.Controls.AddRange([_save, _verify, _close]);

        _output.AccessibleName = "Output";

        root.Controls.Add(header);
        root.Controls.Add(explanation);
        root.Controls.Add(_warning);
        root.Controls.Add(credentials);
        root.Controls.Add(runAsGroup);
        root.Controls.Add(buttons);
        root.Controls.Add(_output);
        for (var i = 0; i < root.Controls.Count - 1; i++)
        {
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        }

        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        return root;
    }

    private void Render()
    {
        var session = Session;
        _secretsPath.Text = session?.SecretsPath ?? "";
        _account.Text = session?.CurrentAccount.ToString() ?? "";
        _changeSecretsPath.Enabled = session is not null;
        UpdateRunAsCommand();

        if (session is null)
        {
            _fieldsTable.Controls.Clear();
            _fields.Clear();
            _warning.Visible = false;
            UpdateButtons();
            return;
        }

        // Rebuild the fields only when the set of credentials changes, so focus and typing aren't lost.
        if (!_fields.Keys.SequenceEqual(session.App.Credentials.Select(c => c.Name)))
        {
            _fieldsTable.SuspendLayout();
            _fieldsTable.Controls.Clear();
            _fieldsTable.RowStyles.Clear();
            _fields.Clear();
            var row = 0;
            foreach (var field in session.App.Credentials)
            {
                var input = new TextBox { Dock = DockStyle.Fill, UseSystemPasswordChar = field.Masked, AccessibleName = field.Prompt, MinimumSize = new Size(240, 0) };
                var status = new Label { AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(6, 4, 0, 4) };
                _fieldsTable.RowStyles.Add(new RowStyle(SizeType.AutoSize));
                _fieldsTable.Controls.Add(CaptionLabel(field.Prompt + ":"), 0, row);
                _fieldsTable.Controls.Add(input, 1, row);
                _fieldsTable.Controls.Add(status, 2, row);
                _fields[field.Name] = (input, status);
                row++;
            }

            _fieldsTable.ResumeLayout();
        }

        foreach (var field in session.App.Credentials)
        {
            var (input, status) = _fields[field.Name];
            status.Text = session.DescribeCredential(field.Name);
            input.PlaceholderText = session.CanKeep(field.Name) ? "Leave blank to keep the current value" : "Required";
        }

        if (session.FileWarning is { } warning)
        {
            ShowWarning(warning);
        }
        else
        {
            _warning.Visible = false;
        }

        UpdateButtons();
    }

    private void ShowWarning(string message)
    {
        _warning.Text = message;
        _warning.Visible = true;
    }

    private void UpdateButtons()
    {
        _save.Enabled = !_busy && Session is { Status.CanSave: true };
        _verify.Enabled = !_busy && Session is { Status.FileState: not SecretFileState.Missing };
        _chooseApp.Enabled = !_busy;
        _changeSecretsPath.Enabled = !_busy && Session is not null;
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        UseWaitCursor = busy;
        UpdateButtons();
    }

    private void UpdateRunAsCommand()
    {
        string command;
        try
        {
            command = _app is null || string.IsNullOrWhiteSpace(_runAsAccount.Text)
                ? ""
                : RunAsCommand.Build(_runAsAccount.Text, _setupToolPath, _app.Path, _secretsPathOverride);
        }
        catch (ArgumentException ex)
        {
            command = ex.Message;
        }

        _runAsCommand.Text = command;
        _copyRunAs.Enabled = command.StartsWith("runas ", StringComparison.Ordinal);
    }

    private async Task ChooseAppAsync()
    {
        if (_prompts.ChooseApp(this) is not { } path)
        {
            if (_app is null)
            {
                ShowWarning("Choose the app whose credentials you want to set up.");
            }

            return;
        }

        _app = _createApp(path);
        _secretsPathOverride = null;
        ClearInputs();
        await LoadAsync();
    }

    private async Task ChangeSecretsPathAsync()
    {
        if (Session is null || _prompts.ChooseSecretsPath(this, Session.SecretsPath) is not { } path)
        {
            return;
        }

        _secretsPathOverride = path;
        ClearInputs();
        await LoadAsync();
    }

    private void AppendOutput(string text)
    {
        if (_output.TextLength > 0)
        {
            _output.AppendText(Environment.NewLine);
        }

        _output.AppendText(text.ReplaceLineEndings(Environment.NewLine));
    }

    private void ClearInputs()
    {
        foreach (var (input, _) in _fields.Values)
        {
            input.Clear();
        }
    }
}
