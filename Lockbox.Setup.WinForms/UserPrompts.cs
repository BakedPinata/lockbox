namespace Lockbox.Setup.WinForms;

/// <summary>The dialogs the form shows. Replaced in tests so nothing blocks.</summary>
internal interface IUserPrompts
{
    bool Confirm(IWin32Window owner, string message);

    void ShowError(IWin32Window owner, string message);

    void ShowInfo(IWin32Window owner, string message);

    /// <summary>Asks for the app to set up, or returns <see langword="null"/> if cancelled.</summary>
    string? ChooseApp(IWin32Window owner);

    /// <summary>Asks for a secrets file path, or returns <see langword="null"/> if cancelled.</summary>
    string? ChooseSecretsPath(IWin32Window owner, string current);

    void CopyToClipboard(string text);
}

internal sealed class DialogPrompts : IUserPrompts
{
    private const string Title = "Lockbox Setup";

    public bool Confirm(IWin32Window owner, string message) =>
        MessageBox.Show(owner, message, Title, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes;

    public void ShowError(IWin32Window owner, string message) =>
        MessageBox.Show(owner, message, Title, MessageBoxButtons.OK, MessageBoxIcon.Error);

    public void ShowInfo(IWin32Window owner, string message) =>
        MessageBox.Show(owner, message, Title, MessageBoxButtons.OK, MessageBoxIcon.Information);

    public string? ChooseApp(IWin32Window owner)
    {
        using var dialog = new OpenFileDialog
        {
            Title = "Choose the app to set up",
            Filter = "Apps (*.exe;*.dll)|*.exe;*.dll|All files (*.*)|*.*",
            CheckFileExists = true,
        };
        return dialog.ShowDialog(owner) == DialogResult.OK ? dialog.FileName : null;
    }

    public string? ChooseSecretsPath(IWin32Window owner, string current)
    {
        using var dialog = new SaveFileDialog
        {
            Title = "Choose the secrets file",
            Filter = "Secrets file (*.json)|*.json|All files (*.*)|*.*",
            FileName = Path.GetFileName(current),
            InitialDirectory = Path.GetDirectoryName(current),
            OverwritePrompt = false,
            CheckFileExists = false,
        };
        return dialog.ShowDialog(owner) == DialogResult.OK ? dialog.FileName : null;
    }

    public void CopyToClipboard(string text) => Clipboard.SetText(text);
}
